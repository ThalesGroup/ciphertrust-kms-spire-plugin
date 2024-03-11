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
	"crypto"
	"crypto/x509"
	b64 "encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/ThalesGroup/ciphertrust-kms-spire-plugin/pkg/ciphertrustkms"

	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
)

type FakeKey struct {
	*ciphertrustkms.Key
	privateKey crypto.Signer
}

type FakeCryptoKey struct {
	mu       sync.RWMutex
	Name     string
	Versions map[int]*FakeKey
}

func (fs *fakeStore) fetchFakeCryptoKeys() map[string]*FakeCryptoKey {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.fakeCryptoKeys == nil {
		return nil
	}

	fakeCryptoKeys := make(map[string]*FakeCryptoKey, len(fs.fakeCryptoKeys))
	for key, fakeCryptoKey := range fs.fakeCryptoKeys {
		fakeCryptoKeys[key] = fakeCryptoKey
	}
	return fakeCryptoKeys
}

func (fck *FakeCryptoKey) getLabelValue(version int, key string) string {
	fck.mu.RLock()
	defer fck.mu.RUnlock()

	return fck.Versions[version].Labels[key]
}

func (fck *FakeCryptoKey) getState(version int) string {
	fck.mu.RLock()
	defer fck.mu.RUnlock()

	return fck.Versions[version].State
}

func (fck *FakeCryptoKey) putFakeCryptoKeyVersion(fk *FakeKey) {
	fck.mu.Lock()
	defer fck.mu.Unlock()

	fck.Versions[fk.Version] = fk
}

// Simulate the spire cache
type fakeStore struct {
	mu             sync.RWMutex
	fakeCryptoKeys map[string]*FakeCryptoKey

	clk *clock.Mock
}

func (fs *fakeStore) putFakeCryptoKey(fck *FakeCryptoKey) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.fakeCryptoKeys[fck.Name] = fck

}

type fakeKMSClientCipherTrust struct {
	t *testing.T

	mu    sync.RWMutex
	store fakeStore
}

func newKMSClientFake(t *testing.T, c *clock.Mock) *fakeKMSClientCipherTrust {
	return &fakeKMSClientCipherTrust{
		store: newFakeStore(c),
		t:     t,
	}
}

func newFakeStore(c *clock.Mock) fakeStore {
	return fakeStore{
		fakeCryptoKeys: make(map[string]*FakeCryptoKey),
		clk:            c,
	}
}

/**Simulate the cipher KMS interface**/

func (fc *fakeKMSClientCipherTrust) AsymmetricSignCipherTrust(ctx context.Context, KeyName string, keyVersion int, data []byte) (*ciphertrustkms.SignResponse, error) {
	return &ciphertrustkms.SignResponse{}, nil
}

func (fc *fakeKMSClientCipherTrust) CreateCryptoKeyVersionCipherTrust(ctx context.Context, keyId string) (*ciphertrustkms.CipherTrustCryptoKey, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fck, ok := fc.store.fakeCryptoKeys[keyId]
	if !ok {
		return nil, fmt.Errorf("could not find parent CryptoKey %q", keyId)
	}
	var lastVersion = 0
	for k := range fck.Versions {
		lastVersion = k
	}

	fakeKey := FakeKey{
		Key: &ciphertrustkms.Key{
			Name:    fck.Versions[lastVersion].Name,
			Labels:  fck.Versions[lastVersion].Labels,
			KeyID:   fck.Versions[lastVersion].KeyID,
			CurveID: "prime256v1",
		},
	}

	fckv, err := fc.createFakeCryptoKeyVersion(&fakeKey, lastVersion+1)
	if err != nil {
		return nil, err
	}

	fck.putFakeCryptoKeyVersion(fckv)

	key := ciphertrustkms.CipherTrustCryptoKey{}
	key.Key = *fckv.Key

	return &key, nil
}

func (fc *fakeKMSClientCipherTrust) CreateCryptoKeyCipherTrust(ctx context.Context, cryptoKeyId string, labels map[string]string) (*ciphertrustkms.CipherTrustCryptoKey, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	fakeKey := FakeKey{
		Key: &ciphertrustkms.Key{
			Name:    cryptoKeyId,
			Labels:  labels,
			CurveID: "prime256v1",
		},
	}

	fck_, err := fc.createFakeCryptoKeyVersion(&fakeKey, 0)
	if err != nil {
		return nil, err
	}

	v := make(map[int]*FakeKey) //First time create the version map
	v[0] = &fakeKey

	fck := &FakeCryptoKey{
		Name:     fck_.Name,
		Versions: v,
	}

	fc.store.putFakeCryptoKey(fck)
	key := ciphertrustkms.CipherTrustCryptoKey{}
	key.Key = *fakeKey.Key

	return &key, nil

}
func (k *fakeKMSClientCipherTrust) createFakeCryptoKeyVersion(cryptoKey *FakeKey, version int) (*FakeKey, error) {
	var privateKey crypto.Signer
	var testKeys testkey.Keys

	switch cryptoKey.CurveID {
	case "prime256v1":
		privateKey = testKeys.NewEC256(k.t)
	default:
		return nil, fmt.Errorf("unknown algorithm %q", cryptoKey.CurveID)
	}

	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	cryptoKey.State = "Active"
	cryptoKey.CurveID = "prime256v1"
	cryptoKey.PublicKey = "-----BEGIN PUBLIC KEY-----\n" + b64.StdEncoding.EncodeToString(pkixData) + "\n-----END PUBLIC KEY-----\n"
	cryptoKey.privateKey = privateKey
	cryptoKey.Version = version

	return cryptoKey, nil
}

func (fc *fakeKMSClientCipherTrust) GetPublicKeyCipherTrust(ctx context.Context, key *ciphertrustkms.Key) (*ciphertrustkms.CipherTrustCryptoKey, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	key_ := ciphertrustkms.CipherTrustCryptoKey{}
	key_.Key = *key
	return &key_, nil
}

func (fc *fakeKMSClientCipherTrust) ListCryptoKeyVersionsCipherTrust(ctx context.Context, id string, filter string) (*ciphertrustkms.CipherTrustCryptoKeysList, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	keys := ciphertrustkms.CipherTrustCryptoKeysList{}
	keysTmp := []*ciphertrustkms.Key{}
	fakeCryptoKeys := fc.store.fetchFakeCryptoKeys()
	for _, fckv := range fakeCryptoKeys {
		for _, fck := range fckv.Versions {
			keysTmp = append(keysTmp, fck.Key)
			keys.Keys = keysTmp
		}
	}
	return &keys, nil
}

func (fc *fakeKMSClientCipherTrust) ListCryptoKeysCipherTrust(ctx context.Context, filter string) (*ciphertrustkms.CipherTrustCryptoKeysList, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	keys := ciphertrustkms.CipherTrustCryptoKeysList{}
	keysTmp := []*ciphertrustkms.Key{}
	fakeCryptoKeys := fc.store.fetchFakeCryptoKeys()

	for _, fck := range fakeCryptoKeys {
		for _, fckv := range fck.Versions {
			// We Have a simplified filtering logic in this fake implementation,
			// where we only support filtering by enabled status.

			if fckv.State != "Active" {
				fc.t.Fatal("Unsupported filter in ListCryptoKeyVersions request")
			}
			if fckv.State != "Active" {
				continue
			}

			keysTmp = append(keysTmp, fckv.Key)
			keys.Keys = keysTmp
		}
	}
	return &keys, nil
}

func (k *fakeKMSClientCipherTrust) putFakeCryptoKeys(fakeCryptoKeys []*FakeCryptoKey) {
	for _, fck := range fakeCryptoKeys {
		k.store.putFakeCryptoKey(&FakeCryptoKey{
			Name:     fck.Name,
			Versions: fck.Versions,
		})
	}
}
func (k *fakeKMSClientCipherTrust) UpdateCryptoKeyCipherTrust(ctx context.Context, cryptokey *ciphertrustkms.Key) (*ciphertrustkms.Key, error) {

	fakeCryptoKeys := k.store.fetchFakeCryptoKeys()
	for _, fckv := range fakeCryptoKeys {
		for _, fck := range fckv.Versions {
			fck.Labels[ciphertrustkms.LabelNameActive] = cryptokey.Labels[ciphertrustkms.LabelNameActive]
		}
	}

	return cryptokey, nil
}
