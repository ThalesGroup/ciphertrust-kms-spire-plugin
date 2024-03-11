/*
 * Copyright 2024 Thales Group. All Rights Reserved.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package keymanager

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ThalesGroup/ciphertrust-kms-spire-plugin/pkg/ciphertrustkms"

	"sync"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pluginData struct {
	serverID string
	tdHash   string
}
type pluginHooks struct {
	newKMSClient func(context.Context, ...option.ClientOption) (ciphertrustkms.CloudKeyManagementServiceCipherTrust, error)

	Clk clock.Clock

	// Used for testing only.
	DisposeCryptoKeysSignal    chan error
	EnqueueDestructionSignal   chan error
	KeepActiveCryptoKeysSignal chan error
	ScheduleDestroySignal      chan error
	SetInactiveSignal          chan error
}

// Config defines the configuration for the plugin.
type Config struct {
	// File path location where key metadata used by the plugin is persisted.
	KeyMetadataFile string `hcl:"key_metadata_file" json:"key_metadata_file"`
	// Where the CipherTrust instance is running.
	CTMService string `hcl:"ctm_url" json:"ctm_url"`
	// Username to access the CT instance.
	Username string `hcl:"username" json:"username"`
	// Password to access the CT instance.
	Password string `hcl:"password" json:"password"`
}

// Plugin implements the KeyManager plugin
type Plugin struct {
	keymanagerv1.UnimplementedKeyManagerServer
	configv1.UnimplementedConfigServer

	cancelTasks context.CancelFunc

	Config     *Config
	configMtx  sync.RWMutex
	Entries    map[string]ciphertrustkms.KeyEntryCipherTrust
	entriesMtx sync.RWMutex

	pd    *pluginData
	pdMtx sync.RWMutex

	Hooks                pluginHooks
	kmsClientCipherTrust ciphertrustkms.CloudKeyManagementServiceCipherTrust

	Log             hclog.Logger
	scheduleDestroy chan string
}

// NewPlugin returns a new plugin instance.
func NewPlugin(
	newKMSClient func(context.Context, ...option.ClientOption) (ciphertrustkms.CloudKeyManagementServiceCipherTrust, error),
) *Plugin {
	return &Plugin{
		Entries: make(map[string]ciphertrustkms.KeyEntryCipherTrust),
		Hooks: pluginHooks{
			newKMSClient: newKMSClient,
			Clk:          clock.New(),
		},
		scheduleDestroy: make(chan string, 120),
	}
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := parseAndValidateConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}

	serverID, err := getOrCreateServerID(config.KeyMetadataFile)
	if err != nil {
		return nil, err
	}
	p.Log.Debug("Loaded server ID", "server_id", serverID)

	ciphertrustkms.Init(config.CTMService, config.Username, config.Password)
	tdHashBytes := sha1.Sum([]byte(req.CoreConfiguration.TrustDomain)) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid label restrictions
	tdHashString := hex.EncodeToString(tdHashBytes[:])

	p.setPluginData(&pluginData{
		serverID: serverID,
		tdHash:   tdHashString,
	})

	var opts []option.ClientOption

	kc, err := p.Hooks.newKMSClient(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Google Cloud KMS client: %v", err)
	}

	fetcher := &ciphertrustkms.KeyFetcher{
		KmsClientCipherTrust: kc,
		Log:                  p.Log,
		ServerID:             serverID,
		TdHash:               tdHashString,
	}
	p.Log.Debug("Fetching keys from Cloud KMS\n")
	keyEntries, err := fetcher.FetchKeyEntriesCipherTrust(ctx)
	if err != nil {
		return nil, err
	}

	p.setCacheCipherTrust(keyEntries)
	p.kmsClientCipherTrust = kc

	// Cancel previous tasks in case of re configure.
	if p.cancelTasks != nil {
		p.cancelTasks()
	}

	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.Config = config

	// Start long-running tasks.
	ctx, p.cancelTasks = context.WithCancel(context.Background())
	//go p.scheduleDestroyTask(ctx)
	go p.keepActiveCryptoKeysTask(ctx)
	go p.disposeCryptoKeysTask(ctx)

	return &configv1.ConfigureResponse{}, nil
}

// GenerateKey implements the KeyManager GenerateKey RPC.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}
	pubKey, err := p.createKey(ctx, req.KeyId, req.KeyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
	}

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: pubKey,
	}, nil
}

// createKey creates a new CryptoKey with a new CryptoKeyVersion in Cloud KMS
func (p *Plugin) createKey(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keymanagerv1.PublicKey, error) {
	// If we already have this SPIRE Key ID cached, a new CryptoKeyVersion is
	// added to the existing CryptoKey and the cache is updated.
	if entry, ok := p.getKeyEntryCipherTrust(spireKeyID); ok {
		return p.addCryptoKeyVersionToCachedEntryCipherTrust(ctx, entry, spireKeyID, keyType)
	}

	algorithm, err := cryptoKeyVersionAlgorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	cryptoKeyID, err := p.generateCryptoKeyID(spireKeyID)
	if err != nil {
		return nil, fmt.Errorf("could not generate CryptoKeyID: %w", err)
	}

	cryptoKeyLabels, err := p.getCryptoKeyLabels()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not get CryptoKey labels: %v", err)
	}
	cryptoKeyCipherTrust, err := p.kmsClientCipherTrust.CreateCryptoKeyCipherTrust(ctx, cryptoKeyID, cryptoKeyLabels)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create CryptoKey: %v", err)
	}

	log := p.Log.With(ciphertrustkms.CryptoKeyNameTag, cryptoKeyCipherTrust.Key.Name)
	log.Debug("CryptoKey created", ciphertrustkms.AlgorithmTag, algorithm)

	cryptoKeyVersionName := cryptoKeyCipherTrust.Key.Name + "/cryptoKeyVersions/0"

	log.Debug("CryptoKeyVersion version added", ciphertrustkms.CryptoKeyVersionNameTag, cryptoKeyVersionName)

	log.Debug("Public Key Created by CipherTrust\n", cryptoKeyCipherTrust.Key.PublicKey)

	pemBlock, _ := pem.Decode([]byte(cryptoKeyCipherTrust.Key.PublicKey))
	if pemBlock == nil {
		return nil, status.Errorf(codes.Internal, "Failed to decode PEM block")
	}

	newKeyEntry := ciphertrustkms.KeyEntryCipherTrust{
		CryptoKey:            &cryptoKeyCipherTrust.Key,
		CryptoKeyVersionName: cryptoKeyVersionName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}

	p.setKeyEntryCipherTrust(spireKeyID, newKeyEntry)
	return newKeyEntry.PublicKey, nil
}

// getCryptoKeyLabels gets the labels that must be set to a new CryptoKey
// that is being created.
func (p *Plugin) getCryptoKeyLabels() (map[string]string, error) {
	pd, err := p.getPluginData()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		ciphertrustkms.LabelNameServerTD: pd.tdHash,
		ciphertrustkms.LabelNameServerID: pd.serverID,
		ciphertrustkms.LabelNameActive:   "true",
	}, nil
}

// generateCryptoKeyID returns a new identifier to be used as a CryptoKeyID.
// The returned identifier has the form: spire-key-<UUID>-<SPIRE-KEY-ID>,
// where UUID is a new randomly generated UUID and SPIRE-KEY-ID is provided
// through the spireKeyID paramenter.
func (p *Plugin) generateCryptoKeyID(spireKeyID string) (cryptoKeyID string, err error) {
	pd, err := p.getPluginData()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s", ciphertrustkms.CryptoKeyNamePrefix, pd.serverID, spireKeyID), nil
}

// getPluginData gets the pluginData structure maintained by the plugin.
func (p *Plugin) getPluginData() (*pluginData, error) {
	p.pdMtx.RLock()
	defer p.pdMtx.RUnlock()

	if p.pd == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin data not yet initialized")
	}
	return p.pd, nil
}

// cryptoKeyVersionAlgorithmFromKeyType gets the corresponding algorithm of the
// CryptoKeyVersion from the provided key type.
// The returned CryptoKeyVersion_CryptoKeyVersionAlgorithm indicates the
// parameters that must be used for signing.
func cryptoKeyVersionAlgorithmFromKeyType(keyType keymanagerv1.KeyType) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch {
	case keyType == keymanagerv1.KeyType_EC_P256:
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	case keyType == keymanagerv1.KeyType_EC_P384:
		return kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	case keyType == keymanagerv1.KeyType_RSA_2048:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, nil
	case keyType == keymanagerv1.KeyType_RSA_4096:
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, nil
	default:
		return kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// addCryptoKeyVersionToCachedEntry adds a new CryptoKeyVersion to an existing
// CryptoKey, updating the cached entries.
func (p *Plugin) addCryptoKeyVersionToCachedEntryCipherTrust(ctx context.Context, entry ciphertrustkms.KeyEntryCipherTrust, spireKeyID string, keyType keymanagerv1.KeyType) (*keymanagerv1.PublicKey, error) {
	algorithm, err := cryptoKeyVersionAlgorithmFromKeyType(keyType)
	if err != nil {
		return nil, err
	}

	log := p.Log.With(ciphertrustkms.CryptoKeyNameTag, entry.CryptoKey.Name, algorithm)

	cryptoKey, err := p.kmsClientCipherTrust.CreateCryptoKeyVersionCipherTrust(ctx, entry.CryptoKey.Name)

	if err != nil {
		return nil, fmt.Errorf("failed to create CryptoKeyVersion: %w", err)
	}
	log.Debug("CryptoKeyVersion added", ciphertrustkms.CryptoKeyVersionNameTag, cryptoKey.Key.Name+"/"+strconv.Itoa(cryptoKey.Key.Version))

	log.Debug("CryptoKeyVersion added Public key ", cryptoKey.Key.PublicKey)

	pemBlock, _ := pem.Decode([]byte(cryptoKey.Key.PublicKey))

	log.Debug("public key byte from private key : ", pemBlock.Bytes)

	newKeyEntry := ciphertrustkms.KeyEntryCipherTrust{
		CryptoKey:            &cryptoKey.Key,
		CryptoKeyVersionName: cryptoKey.Key.Name + "/" + strconv.Itoa(cryptoKey.Key.Version),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}

	p.setKeyEntryCipherTrust(spireKeyID, newKeyEntry)

	if err := p.enqueueDestruction(entry.CryptoKeyVersionName); err != nil {
		log.Error("Failed to enqueue CryptoKeyVersion for destruction", ciphertrustkms.ReasonTag, err)
	}

	return newKeyEntry.PublicKey, nil
}

// enqueueDestruction enqueues the specified CryptoKeyVersion for destruction.
func (p *Plugin) enqueueDestruction(cryptoKeyVersionName string) (err error) {
	select {
	case p.scheduleDestroy <- cryptoKeyVersionName:
		p.Log.Debug("CryptoKeyVersion enqueued for destruction", ciphertrustkms.CryptoKeyVersionNameTag, cryptoKeyVersionName)
	default:
		err = fmt.Errorf("could not enqueue CryptoKeyVersion %q for destruction", cryptoKeyVersionName)
	}

	p.notifyEnqueueDestruction(err)
	return err
}

// setKeyEntry gets the entry from the cache that matches the provided
// SPIRE Key ID
func (p *Plugin) setKeyEntryCipherTrust(keyID string, ke ciphertrustkms.KeyEntryCipherTrust) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.Entries[keyID] = ke
}

// getKeyEntry gets the entry from the cache that matches the provided
// SPIRE Key ID
func (p *Plugin) getKeyEntryCipherTrust(keyID string) (ke ciphertrustkms.KeyEntryCipherTrust, ok bool) {
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	ke, ok = p.Entries[keyID]
	return ke, ok
}

// GetPublicKey implements the KeyManager GetPublicKey RPC.
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	entry, ok := p.getKeyEntryCipherTrust(req.KeyId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC.
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()
	for _, key := range p.Entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// SignData implements the KeyManager SignData RPC.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	keyEntry, hasKey := p.getKeyEntryCipherTrust(req.KeyId)
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
	case *keymanagerv1.SignDataRequest_PssOptions:
		// RSASSA-PSS is not supported by this plugin.
		return nil, status.Error(codes.InvalidArgument, "the only RSA signature scheme supported is RSASSA-PKCS1-v1_5")
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	signResp, err := p.kmsClientCipherTrust.AsymmetricSignCipherTrust(ctx, keyEntry.CryptoKey.Name, keyEntry.CryptoKey.Version, req.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}
	signatureBytes, err := hex.DecodeString(signResp.Signature)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode signature")
	}

	p.Log.Debug("<- Signature received from CipherTrust\n")
	p.Log.Debug(fmt.Sprintf("%x\n", signatureBytes))

	return &keymanagerv1.SignDataResponse{
		Signature:      signatureBytes,
		KeyFingerprint: keyEntry.PublicKey.Fingerprint,
	}, nil
}

// setCacheCipherTrust sets the cached entries with the provided entries.
func (p *Plugin) setCacheCipherTrust(keyEntries []*ciphertrustkms.KeyEntryCipherTrust) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.Entries = make(map[string]ciphertrustkms.KeyEntryCipherTrust)

	for _, e := range keyEntries {
		p.Entries[e.PublicKey.Id] = *e
		p.Log.Debug("Cloud KMS key loaded", ciphertrustkms.CryptoKeyVersionNameTag, e.CryptoKeyVersionName, ciphertrustkms.AlgorithmTag)
	}
}

// setPluginData sets the pluginData structure maintained by the plugin.
func (p *Plugin) setPluginData(pd *pluginData) {
	p.pdMtx.Lock()
	defer p.pdMtx.Unlock()

	p.pd = pd
}

// parseAndValidateConfig returns an error if any configuration provided does
// not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.KeyMetadataFile == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing key metadate file")
	}
	if config.CTMService == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the CipherTrust service URL")
	}
	if config.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the CipherTrust service Username")
	}
	if config.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing CipherTrust service Password")
	}

	return config, nil
}

// getOrCreateServerID gets the server ID from the specified file path or creates
// a new server ID if the file does not exist.
func getOrCreateServerID(idPath string) (string, error) {
	data, err := os.ReadFile(idPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createServerID(idPath)
	case err != nil:
		return "", status.Errorf(codes.Internal, "failed to read server ID from path: %v", err)
	}

	serverID, err := uuid.FromString(string(data))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to parse server ID from path: %v", err)
	}
	return serverID.String(), nil
}

// createServerID creates a randomly generated UUID to be used as a server ID
// and stores it in the specified idPath.
func createServerID(idPath string) (string, error) {
	id, err := generateUniqueID()
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to generate ID for server: %v", err)
	}

	err = diskutil.WritePrivateFile(idPath, []byte(id))
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to persist server ID on path: %v", err)
	}
	return id, nil
}

// generateUniqueID returns a randomly generated UUID.
func generateUniqueID() (id string, err error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", status.Errorf(codes.Internal, "could not create a randomly generated UUID: %v", err)
	}

	return u.String(), nil
}

// SetLogger is called by the framework when the plugin is loaded.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.Log = logger
}

// disposeCryptoKeysTask will be run every 24hs.
// It will schedule the destruction of CryptoKeyVersions that have a
// spire-last-update label value older than two weeks.
// It will only schedule the destruction of CryptoKeyVersions belonging to the
// current trust domain but not the current server. The spire-server-td and
// spire-server-id labels are used to identify the trust domain and server.
func (p *Plugin) disposeCryptoKeysTask(ctx context.Context) {
	ticker := p.Hooks.Clk.Ticker(ciphertrustkms.DisposeCryptoKeysFrequency)
	defer ticker.Stop()

	p.notifyDisposeCryptoKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.disposeCryptoKeys(ctx)
			p.notifyDisposeCryptoKeys(err)
		}
	}
}

// disposeCryptoKeys looks for active CryptoKeys that haven't been updated
// during the maxStaleDuration time window. Those keys are then enqueued for
// destruction.
func (p *Plugin) disposeCryptoKeys(ctx context.Context) error {
	p.Log.Debug("Dispose CryptoKeys")

	itCryptoKeys, err := p.kmsClientCipherTrust.ListCryptoKeysCipherTrust(ctx, "")
	if err != nil {
		p.Log.Debug("Dispose CryptoKeys", err)
	}

	it := itCryptoKeys.CreateKeyIterator()

	for {
		cryptoKey, ok := it.GetNext()
		if !ok {
			break
		}
		// mark it as inactive so it's not returned future calls.
		p.setDeactivated(ctx, cryptoKey)

	}
	return nil
}

// setDeactivated updates the state in the specified CryptoKey to
// indicate that is deactivated.
func (p *Plugin) setDeactivated(ctx context.Context, cryptoKey *ciphertrustkms.Key) {
	log := p.Log.With(ciphertrustkms.CryptoKeyNameTag, cryptoKey)

	cryptoKey.State = "Deactivated"
	_, err := p.kmsClientCipherTrust.UpdateCryptoKeyCipherTrust(ctx, cryptoKey)
	if err != nil {
		log.Error("Could not update CryptoKey as deactivated", ciphertrustkms.ReasonTag, err)
	}

	log.Debug("CryptoKey updated as deactivated", ciphertrustkms.CryptoKeyNameTag, cryptoKey.Name)
	p.notifyDisposeCryptoKeys(err)
}

// keepActiveCryptoKeysTask updates the CryptoKeys in the cache every 6 hours,
// setting the spire-last-update label to the current (Unix) time.
// This is done to be able to detect CryptoKeys that are inactive (not in use
// by any server).
func (p *Plugin) keepActiveCryptoKeysTask(ctx context.Context) {
	ticker := p.Hooks.Clk.Ticker(ciphertrustkms.KeepActiveCryptoKeysFrequency)
	defer ticker.Stop()

	p.notifyKeepActiveCryptoKeys(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.keepActiveCryptoKeys()
			p.notifyKeepActiveCryptoKeys(err)
		}
	}
}

// keepActiveCryptoKeys keeps CryptoKeys managed by this plugin active updating
// the spire-last-update label with the current Unix time.
func (p *Plugin) keepActiveCryptoKeys() error {
	p.Log.Debug("Keeping CryptoKeys managed by this server active")

	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()
	var errs []string
	for _, entry := range p.Entries {
		entry.CryptoKey.Labels[ciphertrustkms.LabelNameLastUpdate] = fmt.Sprint(p.Hooks.Clk.Now().Unix())
	}

	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, "; "))
	}
	return nil
}

/**Notify**/
func (p *Plugin) notifyDisposeCryptoKeys(err error) {
	if p.Hooks.DisposeCryptoKeysSignal != nil {
		p.Hooks.DisposeCryptoKeysSignal <- err
	}
}
func (p *Plugin) notifyEnqueueDestruction(err error) {
	if p.Hooks.EnqueueDestructionSignal != nil {
		p.Hooks.EnqueueDestructionSignal <- err
	}
}

func (p *Plugin) notifyKeepActiveCryptoKeys(err error) {
	if p.Hooks.KeepActiveCryptoKeysSignal != nil {
		p.Hooks.KeepActiveCryptoKeysSignal <- err
	}
}

// New returns an instantiated plugin.
func New() *Plugin {
	return NewPlugin(ciphertrustkms.NewKMSClient)
}
