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

package ciphertrustkms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KeyFetcher struct {
	KmsClientCipherTrust CloudKeyManagementServiceCipherTrust
	Log                  hclog.Logger
	ServerID             string
	TdHash               string
}

// fetchKeyEntries requests Cloud KMS to get the list of CryptoKeys that are
// active in this server. They are returned as a keyEntry array.
func (kf *KeyFetcher) FetchKeyEntriesCipherTrust(ctx context.Context) ([]*KeyEntryCipherTrust, error) {
	var keyEntriesCipherTrust []*KeyEntryCipherTrust
	var keyEntriesMutex sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	labels := "&labels=" + LabelNameServerTD + "=" + kf.TdHash + "," + LabelNameServerID + "=" + kf.ServerID + "," + LabelNameActive + "=true"
	keys, err := kf.KmsClientCipherTrust.ListCryptoKeysCipherTrust(ctx, labels)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list SPIRE Server keys in Cloud KMS: %v", err)

	}
	it := keys.CreateKeyIterator()

	for {
		cryptoKey, ok := it.GetNext()
		if !ok {
			break
		}
		if cryptoKey.ObjectType == "Public Key" {
			continue
		}

		spireKeyID, ok := GetSPIREKeyIDFromCryptoKeyNameCipherTrust(cryptoKey.Name)
		if !ok {
			kf.Log.Warn("Could not get SPIRE Key ID from CryptoKey", CryptoKeyNameTag, cryptoKey.Name)
			continue
		}
		kf.Log.Debug(spireKeyID)
		kf.Log.Debug(cryptoKey.Name)
		kf.Log.Debug(cryptoKey.KeyID)

		// Trigger a goroutine to get the details of the key
		g.Go(func() error {
			entries, err := kf.getKeyEntriesFromCryptoKeyCipherTrust(ctx, cryptoKey, spireKeyID) //TODO only private key
			if err != nil {
				return err
			}
			if entries == nil {
				return nil
			}

			keyEntriesMutex.Lock()
			keyEntriesCipherTrust = append(keyEntriesCipherTrust, entries...)
			keyEntriesMutex.Unlock()
			return nil
		})

	}
	// Wait for all the detail gathering routines to finish.
	if err := g.Wait(); err != nil {
		statusErr := status.Convert(err)
		return nil, status.Errorf(statusErr.Code(), "failed to fetch entries: %v", statusErr.Message())
	}

	return keyEntriesCipherTrust, nil
}

// getKeyEntriesFromCryptoKey builds an array of keyEntry values from the provided
// CryptoKey. In order to do that, Cloud KMS is requested to list the
// CryptoKeyVersions of the CryptoKey. The public key of the CryptoKeyVersion is
// also retrieved from each CryptoKey to construct each keyEntry.
func (kf *KeyFetcher) getKeyEntriesFromCryptoKeyCipherTrust(ctx context.Context, cryptoKey *Key, spireKeyID string) (keyEntries []*KeyEntryCipherTrust, err error) {
	if cryptoKey == nil {
		return nil, status.Error(codes.Internal, "cryptoKey is nil")
	}

	keyType, ok := keyTypeFromCryptoKeyVersionAlgorithmCipherTrust(cryptoKey.CurveID)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unsupported CryptoKeyVersionAlgorithm: %v", cryptoKey.CurveID)
	}
	pubKey, err := GetPublicKeyFromCryptoKeyVersionCipherTrust(ctx, kf.Log, kf.KmsClientCipherTrust, cryptoKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error getting public key: %v", err)
	}

	keyEntry := &KeyEntryCipherTrust{
		CryptoKey:            cryptoKey,
		CryptoKeyVersionName: cryptoKey.Name + "/cryptoKeyVersions/" + strconv.Itoa(cryptoKey.Version),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pubKey,
			Fingerprint: makeFingerprint(pubKey),
		},
	}

	keyEntries = append(keyEntries, keyEntry)

	return keyEntries, nil
}

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

// getPublicKeyFromCryptoKeyVersion requests Cloud KMS to get the public key
// of the specified CryptoKeyVersion.
func GetPublicKeyFromCryptoKeyVersionCipherTrust(ctx context.Context, log hclog.Logger, kmsClientCipherTrust CloudKeyManagementServiceCipherTrust, key *Key) ([]byte, error) {
	kmsPublicKey, errGetPublicKey := kmsClientCipherTrust.GetPublicKeyCipherTrust(ctx, key)
	attempts := 1

	log = log.With(CryptoKeyVersionNameTag, key.Name+"/cryptoKeyVersions/"+strconv.Itoa(key.Version))
	for errGetPublicKey != nil {
		if attempts > GetPublicKeyMaxAttempts {
			log.Error("Could not get the public key because the CryptoKeyVersion is still being generated. Maximum number of attempts reached.")
			return nil, errGetPublicKey
		}

		// Check if the CryptoKeyVersion is still being generated or
		// if it is now enabled.
		// Longer generation times can be observed when using algorithms
		// with large key sizes. (e.g. when rsa-4096 keys are used).
		// One or two additional attempts is usually enough to find the
		// CryptoKeyVersion enabled.
		switch kmsPublicKey.Key.State {
		case "Pre-Active":
			// This is a recoverable error.
		case "Active":
			// The CryptoKeyVersion may be ready to be used now.
		default:
			// We cannot recover if it's in a different status.
			return nil, errGetPublicKey
		}

		log.Warn("Could not get the public key because the CryptoKeyVersion is still being generated. Trying again.")
		attempts++
		kmsPublicKey, errGetPublicKey = kmsClientCipherTrust.GetPublicKeyCipherTrust(ctx, key)
	}

	pemBlock, _ := pem.Decode([]byte(kmsPublicKey.Key.PublicKey))

	log.Debug("Public Key from CipherTrust: \n", pemBlock.Bytes)
	return pemBlock.Bytes, nil
}

// getSPIREKeyIDFromCryptoKeyName parses a CryptoKey resource name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func GetSPIREKeyIDFromCryptoKeyNameCipherTrust(cryptoKeyName string) (string, bool) {
	// Get the last element of the path.
	i := 0

	// The i index will indicate us where
	// "spire-key-1f2e225a-91d8-4589-a4fe-f88b7bb04bac-x509-CA-A" starts.
	// Now we have to get the position where the SPIRE Key ID starts.
	// For that, we need to add the length of the CryptoKey name prefix that we
	// are using, the UUID length, and the two "-" separators used in our format.
	spireKeyIDIndex := i + len(CryptoKeyNamePrefix) + 38 // 38 is the UUID length plus two '-' separators
	if spireKeyIDIndex >= len(cryptoKeyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := cryptoKeyName[spireKeyIDIndex:]
	return spireKeyID, true
}

// keyTypeFromCryptoKeyVersionAlgorithm gets the KeyType that corresponds to the
// given algo string
func keyTypeFromCryptoKeyVersionAlgorithmCipherTrust(algorithm string) (keymanagerv1.KeyType, bool) {
	switch algorithm {
	//code definition in a structure that matches the same name and the same value
	case "prime256v1":
		return keymanagerv1.KeyType_EC_P256, true
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, false
	}
}
