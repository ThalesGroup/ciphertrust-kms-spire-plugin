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

package keymanager_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	keymanagerctm "github.com/ThalesGroup/ciphertrust-kms-spire-plugin/pkg/keymanager"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spireKeyID1       = "spireKeyID-1"
	spireKeyID2       = "spireKeyID-2"
	testTimeout       = 60 * time.Second
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	metaDataFilePath  = "../metadata/ctmkms-key"
	ctmService        = "https://<local/remote IP/name>"
	username          = "user"
	pwd               = "pwd"
	HclConfiguration  = `
	key_metadata_file = "` + metaDataFilePath + `"
	ctm_url = "` + ctmService + `"
	username = "` + username + `"
	password = "` + pwd + `"
`
)

var (
	sum256 = sha256.Sum256(nil)
)

func Test(t *testing.T) {
	plugin := keymanagerctm.New()
	kmClient := new(keymanagerv1.KeyManagerPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	// Serve the plugin in the background with the configured plugin and
	// service servers. The servers will be cleaned up when the test finishes.
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: keymanagerv1.KeyManagerPluginServer(plugin),
		PluginClient: kmClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  HclConfiguration,
	})
	assert.NoError(t, err)

	require.True(t, kmClient.IsInitialized())

	/**Generate 2 keys**/
	_, err = kmClient.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
		KeyId:   spireKeyID1,
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	assert.NoError(t, err)

	_, err = kmClient.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
		KeyId:   spireKeyID2,
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	assert.NoError(t, err)

	_, err = kmClient.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})
	assert.NoError(t, err)

	_, err = kmClient.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
		KeyId: spireKeyID1,
	})
	assert.NoError(t, err)

	_, err = kmClient.SignData(ctx, &keymanagerv1.SignDataRequest{
		KeyId: spireKeyID1,
		Data:  sum256[:],
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	assert.NoError(t, err)
}
