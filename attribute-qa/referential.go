// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// The canonical attribute referential, read live from the IdP.
//
// The suite never hard-codes an attribute list. The referential is the single
// source of truth the wallet, the SDK, Drive and the IdP all derive from, so a
// QA tool carrying its own copy would drift and start asserting yesterday's
// platform. Every expectation below is expressed in terms of what the
// referential SAYS — "the government twin of birthdate" rather than
// "birthdate_id" — which is also the only way these tests survive the next
// attribute being added.

import (
	"fmt"
	"sort"
	"strings"
)

// Attribute is one entry of the referential.
type Attribute struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Scope      string `json:"scope"`
	Assurance  string `json:"assurance"`
	RequestOnly bool  `json:"requestOnly"`
	// GovKey names the government-backed twin of a self-asserted key. Its
	// presence is what makes a key dual-tier.
	GovKey string `json:"govKey"`
	// CertifiedField is the chip field a government key certifies.
	CertifiedField string `json:"certifiedField"`
	Marketplace    *struct {
		Key      string `json:"key"`
		Billable bool   `json:"billable"`
	} `json:"marketplace"`
}

func (a Attribute) IsGovVerified() bool { return a.Assurance == "gov_verified" }

// IsPriced reports whether disclosing this attribute moves credits.
func (a Attribute) IsPriced() bool { return a.Marketplace != nil && a.Marketplace.Billable }

// Referential is the whole list, indexed.
type Referential struct {
	Attributes []Attribute `json:"attributes"`
	ByKey      map[string]Attribute
}

// LoadReferential fetches the live list from the IdP.
func LoadReferential(c *IdPClient) (*Referential, error) {
	var ref Referential
	if err := c.getJSON("/referential/canonical-attributes.json", &ref); err != nil {
		return nil, fmt.Errorf("referential: %w", err)
	}
	if len(ref.Attributes) == 0 {
		return nil, fmt.Errorf("referential: empty")
	}
	ref.ByKey = make(map[string]Attribute, len(ref.Attributes))
	for _, a := range ref.Attributes {
		ref.ByKey[a.Key] = a
	}
	return &ref, nil
}

// DualTierPairs returns every self-asserted key that has a government twin,
// which is the relationship the whole `_id` convention exists to express.
func (r *Referential) DualTierPairs() [][2]Attribute {
	var out [][2]Attribute
	for _, a := range r.Attributes {
		if a.GovKey == "" {
			continue
		}
		if gov, ok := r.ByKey[a.GovKey]; ok {
			out = append(out, [2]Attribute{a, gov})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0].Key < out[j][0].Key })
	return out
}

// InScope reports whether a scope string reaches this attribute without it
// being named. Request-only keys are reachable no other way than by naming.
func (a Attribute) InScope(scope string) bool {
	if a.RequestOnly || a.Scope == "" {
		return false
	}
	return strings.Contains(scope, a.Scope)
}

// SelfAsserted returns the keys of the referential that a test identity can
// actually deliver, so a suite can build a request it is able to satisfy.
func (r *Referential) SelfAsserted() []Attribute {
	var out []Attribute
	for _, a := range r.Attributes {
		if !a.IsGovVerified() {
			out = append(out, a)
		}
	}
	return out
}

// Priced returns every attribute whose disclosure is billable.
func (r *Referential) Priced() []Attribute {
	var out []Attribute
	for _, a := range r.Attributes {
		if a.IsPriced() {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
