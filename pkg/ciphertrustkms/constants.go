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

import "time"

const (
	PluginName = "ciphertrust_kms"

	AlgorithmTag             = "algorithm"
	CryptoKeyNameTag         = "crypto_key_name"
	CryptoKeyVersionNameTag  = "crypto_key_version_name"
	CryptoKeyVersionStateTag = "crypto_key_version_state"
	ScheduledDestroyTimeTag  = "scheduled_destroy_time"
	ReasonTag                = "reason"

	DisposeCryptoKeysFrequency    = time.Hour * 24
	KeepActiveCryptoKeysFrequency = time.Hour * 6
	MaxStaleDuration              = time.Hour * 24 * 14 // Two weeks

	CryptoKeyNamePrefix = "spire-key"
	LabelNameServerID   = "spire-server-id"
	LabelNameLastUpdate = "spire-last-update"
	LabelNameServerTD   = "spire-server-td"
	LabelNameActive     = "spire-active"

	GetPublicKeyMaxAttempts = 10
)
