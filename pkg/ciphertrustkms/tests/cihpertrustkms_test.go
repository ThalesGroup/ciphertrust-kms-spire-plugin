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

package ciphertrustkms_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/ThalesGroup/ciphertrust-kms-spire-plugin/pkg/ciphertrustkms"
	keymanagerctm "github.com/ThalesGroup/ciphertrust-kms-spire-plugin/pkg/keymanager"

	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
)

const (
	spireKeyID1       = "spireKeyID-1"
	spireKeyID2       = "spireKeyID-2"
	testTimeout       = 60 * time.Second
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	ctmService        = "https://<local/remote IP/name>"
	username          = "user"
	pwd               = "pwd"
)

var (
	ctx            = context.Background()
	cryptoKeyName1 = fmt.Sprintf("spire-key-%s-spireKeyID-1", validServerID)
	cryptoKeyName2 = fmt.Sprintf("spire-key-%s-spireKeyID-2", validServerID)
	unixEpoch      = time.Unix(0, 0)
	pubKeyFake     = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEki9F9qnTdHPQW01lsW++cttsgtxM\nRjGkgxU7bRTzOrabnzeZs81AEnQzO0f9Lu6ZBhnJeA2/mvghFcyxj8Itqw==\n-----END PUBLIC KEY-----\n"
	sum256         = sha256.Sum256(nil)
)

type pluginTest struct {
	plugin        *keymanagerctm.Plugin
	fakeKMSClient *fakeKMSClientCipherTrust
	log           logrus.FieldLogger
	logHook       *test.Hook
	clockHook     *clock.Mock
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := clock.NewMock(t)
	c.Set(unixEpoch)
	fakeKMSClient := newKMSClientFake(t, c)
	p := keymanagerctm.NewPlugin(
		func(ctx context.Context, opts ...option.ClientOption) (ciphertrustkms.CloudKeyManagementServiceCipherTrust, error) {
			return fakeKMSClient, nil
		},
	)
	kmClient := new(keymanagerv1.KeyManagerPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: keymanagerv1.KeyManagerPluginServer(p),
		PluginClient: kmClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(p),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	p.Hooks.Clk = c

	return &pluginTest{
		plugin:        p,
		fakeKMSClient: fakeKMSClient,
		log:           log,
		logHook:       logHook,
		clockHook:     c,
	}
}

func TestKeepActiveCryptoKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *keymanagerctm.Config
		fakeCryptoKeys   []*FakeCryptoKey
		name             string
	}{
		{
			name: "keep active CryptoKeys succeeds",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.plugin.Hooks.KeepActiveCryptoKeysSignal = make(chan error)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			// Wait for keepActiveCryptoKeys task to be initialized.
			_ = waitForSignal(t, ts.plugin.Hooks.KeepActiveCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(6 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for keepActiveCryptoKeys to be run.
			err = waitForSignal(t, ts.plugin.Hooks.KeepActiveCryptoKeysSignal)

			require.NoError(t, err)

			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeCryptoKey := range storedFakeCryptoKeys {
				for _, fakeKey := range fakeCryptoKey.Versions {
					require.EqualValues(t, fakeCryptoKey.getLabelValue(fakeKey.Version, ciphertrustkms.LabelNameLastUpdate), fmt.Sprint(currentTime.Unix()), fakeCryptoKey.Name)
				}
			}
		})
	}
}

func TestConfigureCipherTrust(t *testing.T) {
	for _, tt := range []struct {
		name             string
		expectMsg        string
		expectCode       codes.Code
		config           *keymanagerctm.Config
		configureRequest *configv1.ConfigureRequest
		fakeCryptoKeys   []*FakeCryptoKey
	}{
		{
			name: "missing key metadata file",
			config: &keymanagerctm.Config{
				KeyMetadataFile: "",
			},
			expectMsg:  "configuration is missing key metadate file",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing CipherTrust service",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				Username:        username,
				Password:        pwd,
			},
			expectMsg:  "configuration is missing the CipherTrust service URL",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing CipherTrust service username",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Password:        pwd,
			},
			expectMsg:  "configuration is missing the CipherTrust service Username",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing CipherTrust service password",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
			},
			expectMsg:  "configuration is missing CipherTrust service Password",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "pass with keys",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},

				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)

			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}
			require.NoError(t, err)

			// Assert the config settings
			require.Equal(t, tt.config, ts.plugin.Config)

			// Assert that the keys have been loaded
			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, expectedFakeCryptoKey := range storedFakeCryptoKeys {
				spireKeyID, ok := ciphertrustkms.GetSPIREKeyIDFromCryptoKeyNameCipherTrust(expectedFakeCryptoKey.Name)
				require.True(t, ok)

				entry, ok := ts.plugin.Entries[spireKeyID]
				require.True(t, ok)
				require.Equal(t, expectedFakeCryptoKey.Name, entry.CryptoKey.Name)
			}

		})
	}
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *keymanagerctm.Config
		expectCode       codes.Code
		expectMsg        string
		destroyTime      *timestamp.Timestamp
		fakeCryptoKeys   []*FakeCryptoKey
		generateKeyReq   *keymanagerv1.GenerateKeyRequest
		logs             []spiretest.LogEntry
		name             string
		createKeyErr     error
	}{
		{
			name: "success: EC 256",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},

		{
			name: "success: replace old key",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			var err error

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}

			_, err = ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			resp, err := ts.plugin.GenerateKey(ctx, tt.generateKeyReq)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestDeactivateKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *keymanagerctm.Config
		expectCode       codes.Code
		expectMsg        string
		deactivationDate string
		destroyTime      *timestamp.Timestamp
		fakeCryptoKeys   []*FakeCryptoKey
		generateKeyReq   *keymanagerv1.GenerateKeyRequest
		logs             []spiretest.LogEntry
		name             string
		createKeyErr     error
	}{
		{
			name: "success: state has changed from active to deactivated",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			deactivationDate: time.Now().Add(time.Hour * time.Duration(24)).Format(time.RFC3339Nano),
			expectMsg:        "Deactivated",
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			//pre-req
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.plugin.Hooks.DisposeCryptoKeysSignal = make(chan error)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			// Wait for TestDeactivateKeys task to be initialized.
			_ = waitForSignal(t, ts.plugin.Hooks.DisposeCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(24 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for TestDeactivateKeys to be run.
			err = waitForSignal(t, ts.plugin.Hooks.DisposeCryptoKeysSignal)

			require.NoError(t, err)

			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeCryptoKey := range storedFakeCryptoKeys {
				for _, fakeKey := range fakeCryptoKey.Versions {
					require.EqualValues(t, tt.expectMsg, fakeCryptoKey.getState(fakeKey.Version))
				}
			}

		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		config           *keymanagerctm.Config
		err              string
		fakeCryptoKeys   []*FakeCryptoKey
	}{
		{
			name: "one key",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
		{
			name: "multiple keys",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
		{
			name: "non existing keys",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})

			if tt.err != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)

			// Assert that the keys have been loaded
			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeKey := range storedFakeCryptoKeys {
				for _, versions := range fakeKey.Versions {
					pubKey, err := ciphertrustkms.GetPublicKeyFromCryptoKeyVersionCipherTrust(ctx, ts.plugin.Log, ts.fakeKMSClient, versions.Key)
					require.NoError(t, err)
					require.Equal(t, pubKey, resp.PublicKeys[0].PkixData)
				}
			}

		})
	}
}

func TestGetPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		configureRequest       *configv1.ConfigureRequest
		config                 *keymanagerctm.Config
		expectCodeConfigure    codes.Code
		expectMsgConfigure     string
		expectCodeGetPublicKey codes.Code
		expectMsgGetPublicKey  string
		fakeCryptoKeys         []*FakeCryptoKey
		keyID                  string
	}{
		{
			name: "existing key",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,

					Versions: map[int]*FakeKey{

						0: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,

								Name:    cryptoKeyName1,
								Labels:  map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version: 0,
								State:   "Active",
								CurveID: "prime256v1",
							},
						},
						1: {
							Key: &ciphertrustkms.Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{ciphertrustkms.LabelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
			keyID: spireKeyID1,
		},
		{
			name: "non existing key",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			expectMsgGetPublicKey:  fmt.Sprintf("key %q not found", "wrongkey"),
			expectCodeGetPublicKey: codes.NotFound,
			keyID:                  "wrongkey",
		},
		{
			name: "missing key id",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			expectMsgGetPublicKey:  "key id is required",
			expectCodeGetPublicKey: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			if tt.expectMsgConfigure != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCodeConfigure, tt.expectMsgConfigure)
				return
			}

			require.NoError(t, err)
			resp, err := ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.keyID,
			})
			if tt.expectMsgGetPublicKey != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCodeGetPublicKey, tt.expectMsgGetPublicKey)
				return
			}
			require.NotNil(t, resp)
			require.NoError(t, err)
			require.Equal(t, tt.keyID, resp.PublicKey.Id)
			require.Equal(t, ts.plugin.Entries[tt.keyID].PublicKey, resp.PublicKey)
		})
	}
}

func TestSignData(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *keymanagerctm.Config
		expectCode       codes.Code
		expectMsg        string
		destroyTime      *timestamp.Timestamp
		fakeCryptoKeys   []*FakeCryptoKey
		generateKeyReq   *keymanagerv1.GenerateKeyRequest
		signDataRequest  *keymanagerv1.SignDataRequest
		logs             []spiretest.LogEntry
		name             string
		createKeyErr     error
	}{
		{
			name: "success: signature OK",
			config: &keymanagerctm.Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataRequest: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			var err error

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}

			_, err = ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			genKey, err := ts.plugin.GenerateKey(ctx, tt.generateKeyReq)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, genKey)

			signature, err := ts.plugin.SignData(ctx, tt.signDataRequest)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, signature)
		})
	}
}

func createKeyMetadataFile(t *testing.T, content string) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))

	if content != "" {
		err := os.WriteFile(tempFilePath, []byte(content), 0600)
		if err != nil {
			t.Error(err)
		}
	}
	return tempFilePath
}
func configureRequestFromConfigCipherTrust(c *keymanagerctm.Config) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
            "key_metadata_file":"%s",
			"ctm_url":"%s",
			"username":"%s",
			"password":"%s"
            }`,
			c.KeyMetadataFile,
			c.CTMService,
			c.Username,
			c.Password),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func waitForSignal(t *testing.T, ch chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(testTimeout):
		t.Fail()
	}
	return nil
}
