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
	"net/url"
	"strings"
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

// Workaround for https://github.com/golang/go/issues/16947
// We used to build up the url using sling's BaseURL() and Path() functions
// which delegate to golangs URL.ResolveReference() function.  But this has
// a bug which would cause escaped slashes in URL path components to become
// unescaped, turning a single segment into two segments.
// So we need to build our own absolute paths.
// The golang issue is fixed in 1.8
func abspath(components ...string) string {
	// reusing the same slice here
	noempties := components[:0]
	terminatingSlash := false
	for _, v := range components {
		terminatingSlash = strings.HasSuffix(v, "/")
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "/")
		v = strings.TrimSuffix(v, "/")
		if v != "" {
			noempties = append(noempties, v)
		}
	}
	p := "/" + strings.Join(noempties, "/")
	if terminatingSlash {
		p += "/"
	}
	return p
}

func pathSegmentEscape(s string) string {
	return url.PathEscape(s)
}
