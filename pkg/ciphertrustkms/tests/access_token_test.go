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
	ciphertrustkms "ciphertrust-kms-spire-plugin/pkg/ciphertrustkms"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestToken(t *testing.T) {

	ciphertrustkms.Init(ctmService, username, pwd)
	x, _ := ciphertrustkms.TokenGenerator()
	assert.Contains(t, x.Jwt, "ey")
}
