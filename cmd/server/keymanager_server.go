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

package main

import (
	keymanager_server "ciphertrust-kms-spire-plugin/pkg/keymanager"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

/**plugin entry point**/
func main() {
	plugin := keymanager_server.New()
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
