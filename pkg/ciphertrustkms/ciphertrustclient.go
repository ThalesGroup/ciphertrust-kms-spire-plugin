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

	"google.golang.org/api/option"
)

type CloudKeyManagementServiceCipherTrust interface {
	AsymmetricSignCipherTrust(ctx context.Context, KeyName string, keyVersion int, data []byte) (*SignResponse, error)
	ListCryptoKeysCipherTrust(ctx context.Context, filter string) (*CipherTrustCryptoKeysList, error)
	ListCryptoKeyVersionsCipherTrust(ctx context.Context, id string, filter string) (*CipherTrustCryptoKeysList, error)
	GetPublicKeyCipherTrust(ctx context.Context, key *Key) (*CipherTrustCryptoKey, error)
	CreateCryptoKeyCipherTrust(ctx context.Context, cryptoKeyId string, labels map[string]string) (*CipherTrustCryptoKey, error)
	CreateCryptoKeyVersionCipherTrust(ctx context.Context, keyId string) (*CipherTrustCryptoKey, error)
	UpdateCryptoKeyCipherTrust(ctx context.Context, cryptokey *Key) (*Key, error)
}

type kmsClientCipherTrust struct {
	internalclient *clientApi
}

func (c *kmsClientCipherTrust) AsymmetricSignCipherTrust(ctx context.Context, KeyName string, keyVersion int, data []byte) (*SignResponse, error) {
	return c.internalclient.SignMessage(KeyName, keyVersion, data)
}

func (c *kmsClientCipherTrust) GetPublicKeyCipherTrust(ctx context.Context, key *Key) (*CipherTrustCryptoKey, error) {
	return c.internalclient.GetPubKey(key.Resource.ID)
}

func (c *kmsClientCipherTrust) ListCryptoKeyVersionsCipherTrust(ctx context.Context, id string, filter string) (*CipherTrustCryptoKeysList, error) {
	return c.internalclient.ListCrytoKeyVersions(id, filter)
}

func (c *kmsClientCipherTrust) ListCryptoKeysCipherTrust(ctx context.Context, filter string) (*CipherTrustCryptoKeysList, error) {
	return c.internalclient.ListCryptoKeys(ctx, filter)
}

func (c *kmsClientCipherTrust) CreateCryptoKeyCipherTrust(ctx context.Context, cryptoKeyId string, labels map[string]string) (*CipherTrustCryptoKey, error) {
	return c.internalclient.CreateKey(cryptoKeyId, labels)
}

func (c *kmsClientCipherTrust) CreateCryptoKeyVersionCipherTrust(ctx context.Context, keyId string) (*CipherTrustCryptoKey, error) {
	return c.internalclient.CreateKeyVersion(keyId)
}

func (c *kmsClientCipherTrust) UpdateCryptoKeyCipherTrust(ctx context.Context, cryptokey *Key) (*Key, error) {
	return c.internalclient.UpdateKeyLabel(cryptokey.Name, cryptokey.ID, cryptokey.Labels, cryptokey.Labels)
}
func NewKMSClient(ctx context.Context, opts ...option.ClientOption) (CloudKeyManagementServiceCipherTrust, error) {
	client := new(clientApi)
	return &kmsClientCipherTrust{
		internalclient: client,
	}, nil
}
