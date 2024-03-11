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
	"time"
)

// LinksEndpoint wraps the /vault/links endpoint.
//type LinksEndpoint Client

const (
	// PrivKeyLink is the link to a Private Key
	PrivKeyLink LinkType = "privateKey"
	// PubKeyLink is the link to a Public Key
	PubKeyLink LinkType = "publicKey"
	// CertLink is the link to a Certificate
	CertLink LinkType = "certificate"
	// DerivationBaseObjLink is the link to a Derivation Base object
	DerivationBaseObjLink LinkType = "derivationBaseObject"
	// DerivedKeyLink is the link to a Derived Key
	DerivedKeyLink LinkType = "derivedKey"
	// ReplacementObjLink is the link to a Replacement object
	ReplacementObjLink LinkType = "replacementObject"
	// ReplacedObjLink is the link to a Replaced object
	ReplacedObjLink LinkType = "replacedObject"
	// ParentLink is the link to a Parent Key
	ParentLink LinkType = "parent"
	// ChildLink is the link to a Child Key
	ChildLink LinkType = "child"
	// PreviousLink is the link to a  Previous Key
	PreviousLink LinkType = "previous"
	// NextLink is the link to a Next Key
	NextLink LinkType = "next"
	// Index is a unique index per source
	Index LinkType = "index"
	// PKCS12CertificateLink is the link to a Certificate for pkcs#12 conformant blob
	PKCS12CertificateLink LinkType = "pkcs12Certificate"
	// PKCS12PasswordLink is the link to a Password(SecretData) for pkcs#12 conformant blob
	PKCS12PasswordLink LinkType = "pkcs12Password"
)

// LinkType type
type LinkType string

// LinkParams Parameters used for create and update a Link
type LinkParams struct {
	Type         LinkType `json:"type"`
	Source       string   `json:"source"`
	IDTypeSource string   `json:"idTypeSource,omitempty"`
	Target       string   `json:"target"`
	IDTypeTarget string   `json:"idTypeTarget,omitempty"`
}

// Link represents a link between the source and target
type Link struct {
	Resource
	UpdatedAt time.Time `json:"updatedAt"`
	Type      LinkType  `json:"type"`
	Source    string    `json:"source"`
	SourceID  string    `json:"sourceID"`
	Target    string    `json:"target"`
	TargetID  string    `json:"targetID"`
	Index     int       `json:"index"`
}

// ListLinksParams Parameters used for list links
type ListLinksParams struct {
	Skip   int      `json:"-" url:"skip,omitempty"`
	Limit  int      `json:"-" url:"limit,omitempty"`
	Type   LinkType `json:"-" url:"type,omitempty"`
	Source string   `json:"-" url:"source,omitempty"`
	Target string   `json:"-" url:"target,omitempty"`
	Index  *int     `json:"-" url:"index,omitempty"`
}

// LinksPage is the response to commands that return a set of links
type LinksPage struct {
	PagingInfo
	Resources []Link `json:"resources"`
}
