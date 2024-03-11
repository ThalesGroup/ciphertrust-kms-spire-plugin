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

// Resource is the base set of properties shared by most response structs.
type Resource struct {
	ID  string `json:"id"`
	URI string `json:"uri"`

	// All resources are owned by an account (URI)
	Account     string `json:"account"`
	Application string `json:"application,omitempty"` // deprecated
	DevAccount  string `json:"devAccount,omitempty"`  // deprecated
	// All resources have a created timestamp
	// Auto-set by gorm
	CreatedAt time.Time `json:"createdAt"`
}

// NamedResource : Resource with additional properties - Name and Slug
type NamedResource struct {
	Resource
	Name string `json:"name"`
	Slug string `json:"-"`
}

// Resource2
// yugo Resource is Deprecated: Use Resource2 instead.  The Application and DevAccount fields were never used.
// New resources should be based on Resource2, and existing resources should migrate
// to Resource2 and abandon Application and DevAccount columns over time.
type Resource2 struct {
	// All resources have a GUID primary key
	ID  string `json:"id" `
	URI string `json:"uri"`

	// All resources are owned by an account (URI)
	Account string `json:"account"`

	// All resources have a created timestamp
	// Auto-set by gorm
	CreatedAt time.Time `json:"createdAt"`

	// Labels are used to group and tag resources
	Labels Labels `json:"labels,omitempty"`
}

// Labels can save itself to a database as a JSON string (so it can be mapped natively
// to postgres JSONB columns).
type Labels map[string]string

// PagingInfo is returned by methods which return multiple results.
type PagingInfo struct {
	// Skip is the index of the first result returned.
	Skip int `json:"skip"`
	// Limit is the max number of results returned.
	Limit int `json:"limit"`
	// Total is the total number of results matching the query.
	Total int `json:"total"`
	// Messages contains warning messages about query parameters which were
	// not supported or understood
	Messages []string `json:"messages,omitempty"`
}

// IntPtr is a utility function to turn an int into an int pointer, since
// go can't take a reference to an int literal:
//
//	v := &5  // won't compile
func IntPtr(v int) *int {
	return &v
}
