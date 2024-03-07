/*
 *  Copyright (c) 2024 Thales Group Limited. All Rights Reserved.
 *  This software is the confidential and proprietary information of Thales Group.
 *  
 *  Thales Group MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF 
 *  THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 *  TO THE IMPLIED WARRANTIES OR MERCHANTABILITY, FITNESS FOR A
 *  PARTICULAR PURPOSE, OR NON-INFRINGEMENT. Thales Group SHALL NOT BE
 *  LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS RESULT OF USING,
 *  MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.

 *  THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
 *  CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
 *  PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
 *  NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
 *  SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 *  SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 *  PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). Thales Group
 *  SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FTNESS FOR
 *  HIGH RISK ACTIVITIES;
 *
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
