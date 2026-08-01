// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// The assertions.
//
// Each case states one rule of the attribute model and drives the real
// platform until that rule either holds or does not. They are written against
// the referential rather than a fixed key list, so adding an attribute does
// not silently narrow the suite.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// errSkip marks a case the environment cannot support, as opposed to one the
// platform failed.
//
// The distinction earns its keep: dev carries no `privasys` attribute provider,
// so every pricing case there fails for a reason that says nothing about the
// code. A suite that cries wolf on a fresh environment is a suite people learn
// to ignore, and then it stops catching the real thing.
type errSkip struct{ reason string }

func (e errSkip) Error() string { return "skipped: " + e.reason }

func skip(format string, args ...any) error {
	return errSkip{reason: fmt.Sprintf(format, args...)}
}

func isSkip(err error) bool {
	_, ok := err.(errSkip)
	return ok
}

// marketplaceProvisioned reports whether this control plane sells the platform's
// own attributes at all.
func (e *Env) marketplaceProvisioned() bool {
	priced := e.Ref.Priced()
	if len(priced) == 0 {
		return false
	}
	c, err := e.client("probe", []string{priced[0].Key})
	if err != nil {
		return false
	}
	_, err = e.Platform.QuoteAttributes(c.ClientID, []string{priced[0].Marketplace.Key})
	return err == nil
}

// Case is one QA assertion.
type Case struct {
	Name string
	// Why records what breaks in production if this case fails. A test whose
	// purpose is not written down gets deleted the first time it is
	// inconvenient.
	Why  string
	Run  func(*Env) error
}

// Env is everything a case needs.
type Env struct {
	IdP      *IdPClient
	Platform *PlatformClient
	Ref      *Referential
	Identity *Identity
	Redirect string
	// clients caches relying parties registered during this run, keyed by the
	// whitelist that defines them.
	clients map[string]*OAuthClient
}

// client returns a relying party with an exact whitelist, reusing one from a
// previous run where possible.
//
// Reuse matters: a client registered per run would leave a growing pile of
// relying parties on the account, and the pile is indistinguishable from real
// integrations. The name encodes the whitelist so a match is exact — a client
// whose ceiling has drifted is never silently reused, because the ceiling is
// the thing most of these cases are about.
//
// A reused client cannot return its secret (the platform shows it once), so
// cases needing a token exchange register a fresh one.
func (e *Env) client(label string, attrs []string) (*OAuthClient, error) {
	sorted := append([]string(nil), attrs...)
	sort.Strings(sorted)
	name := "qa-" + label + "-" + shortHash(strings.Join(sorted, ","))

	if e.clients == nil {
		e.clients = map[string]*OAuthClient{}
	}
	if c, ok := e.clients[name]; ok {
		return c, nil
	}

	existing, err := e.Platform.ListClients()
	if err == nil {
		for i := range existing {
			if existing[i].ClientName == name {
				e.clients[name] = &existing[i]
				return &existing[i], nil
			}
		}
	}

	c, err := e.Platform.RegisterClient(name, []string{e.Redirect}, attrs, false)
	if err != nil {
		return nil, err
	}
	e.clients[name] = c
	return c, nil
}

// confidentialClient always registers a fresh relying party, because the
// platform returns a client secret exactly once and a reused client cannot
// complete a token exchange without it.
func (e *Env) confidentialClient(label string, attrs []string) (*OAuthClient, error) {
	return e.Platform.RegisterClient("qa-"+label+"-"+randHex(4),
		[]string{e.Redirect}, attrs, false)
}

// shortHash names a whitelist stably and briefly.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func keysOf(attrs []Attribute) []string {
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a.Key)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Cases is the suite, in the order a reader should meet them.
func Cases() []Case {
	return []Case{
		{
			Name: "a client that names no attribute is refused at registration",
			Why:  "an empty whitelist used to mean 'everything the scope reaches'; a client registered that way now receives nothing, so accepting the registration would hand somebody a relying party that can never sign anyone in",
			Run: func(e *Env) error {
				_, err := e.Platform.RegisterClient("qa-empty-"+randHex(4),
					[]string{e.Redirect}, nil, false)
				if got := statusOf(err); got != http.StatusBadRequest {
					return fmt.Errorf("registration with no attributes returned %s, want 400", describeErr(err))
				}
				return nil
			},
		},
		{
			Name: "the whitelist is a ceiling a request cannot escape",
			Why:  "a registration is a promise about what a relying party may ever ask for; if naming a key on the request could exceed it, the promise is decorative and a client could acquire a passport disclosure by editing a query string",
			Run: func(e *Env) error {
				c, err := e.client("ceiling", []string{"email"})
				if err != nil {
					return err
				}
				var overreach []string
				for _, pair := range e.Ref.DualTierPairs() {
					overreach = append(overreach, pair[1].Key)
				}
				if len(overreach) == 0 {
					return fmt.Errorf("referential exposes no government-backed twin to attempt")
				}
				auth, _, err := e.IdP.Authorize(SignInRequest{
					ClientID: c.ClientID, RedirectURI: e.Redirect,
					Scope: "openid email identity", Attributes: overreach,
				})
				if err != nil {
					return err
				}
				// Guard against the vacuous pass: if the response carried no
				// list at all, "nothing escaped" would be true and meaningless.
				if !contains(auth.RequestedAttributes, "email") {
					return fmt.Errorf("authorize reported no requested attributes at all (got %v); "+
						"the assertion below would pass for the wrong reason", auth.RequestedAttributes)
				}
				for _, k := range overreach {
					if contains(auth.RequestedAttributes, k) {
						return fmt.Errorf("%s escaped a whitelist of [email]", k)
					}
				}
				return nil
			},
		},
		{
			Name: "a whitelisted government key stays out until the scope admits it",
			Why:  "a registration names a request-only key too, otherwise a migrated client could never reach the passport disclosure it used to get; the scope clause is what stops that naming from billing the client on every sign-in, including the ones that never asked for identity",
			Run: func(e *Env) error {
				var gov []string
				for _, a := range e.Ref.Attributes {
					if a.IsGovVerified() && a.RequestOnly && a.Scope == "identity" {
						gov = append(gov, a.Key)
					}
				}
				sort.Strings(gov)
				if len(gov) == 0 {
					return fmt.Errorf("referential exposes no identity-scoped government key")
				}
				c, err := e.client("scope-gate", append([]string{"email"}, gov...))
				if err != nil {
					return err
				}
				// Whitelisted — which counts as naming — but the request asks
				// for a scope that does not reach the identity tier.
				auth, _, err := e.IdP.Authorize(SignInRequest{
					ClientID: c.ClientID, RedirectURI: e.Redirect,
					Scope: "openid email profile",
				})
				if err != nil {
					return err
				}
				if !contains(auth.RequestedAttributes, "email") {
					return fmt.Errorf("authorize reported %v; the assertion below would pass for the wrong reason",
						auth.RequestedAttributes)
				}
				for _, k := range gov {
					if contains(auth.RequestedAttributes, k) {
						return fmt.Errorf("%s was requested without the identity scope", k)
					}
				}

				// And the other half: once the scope admits it, the
				// registration alone is enough to reach it.
				withIdentity, _, err := e.IdP.Authorize(SignInRequest{
					ClientID: c.ClientID, RedirectURI: e.Redirect,
					Scope: "openid email identity",
				})
				if err != nil {
					return err
				}
				for _, k := range gov {
					if !contains(withIdentity.RequestedAttributes, k) {
						return fmt.Errorf("%s was whitelisted and in scope but not requested", k)
					}
				}
				return nil
			},
		},
		{
			Name: "naming a request-only key inside the ceiling reaches it",
			Why:  "the other half of the previous rule: if naming did not work either, a whitelisted government key would be unreachable and the migration that rewrote clients onto `_id` spellings would have taken away their disclosure",
			Run: func(e *Env) error {
				pairs := e.Ref.DualTierPairs()
				if len(pairs) == 0 {
					return fmt.Errorf("referential exposes no dual-tier pair")
				}
				gov := pairs[0][1]
				c, err := e.client("named", []string{"email", gov.Key})
				if err != nil {
					return err
				}
				auth, _, err := e.IdP.Authorize(SignInRequest{
					ClientID: c.ClientID, RedirectURI: e.Redirect,
					Scope: "openid email identity", Attributes: []string{gov.Key},
				})
				if err != nil {
					return err
				}
				if !contains(auth.RequestedAttributes, gov.Key) {
					return fmt.Errorf("%s was whitelisted and named but not requested", gov.Key)
				}
				if req, ok := auth.AttributeRequirements[gov.Key]; !ok || req.Assurance != "gov" {
					return fmt.Errorf("%s asked for assurance %q, want gov", gov.Key, req.Assurance)
				}
				return nil
			},
		},
		{
			Name: "the two tiers of a pair are different attributes",
			Why:  "the bare key is what the holder typed and the `_id` key is what a passport certifies; if they collapsed, a relying party would either be charged for a value nobody verified or handed a self-asserted answer where it needed proof",
			Run: func(e *Env) error {
				pairs := e.Ref.DualTierPairs()
				if len(pairs) == 0 {
					return fmt.Errorf("referential exposes no dual-tier pair")
				}
				for _, pair := range pairs {
					self, gov := pair[0], pair[1]
					if self.IsGovVerified() {
						return fmt.Errorf("%s is marked government-verified; it is the self-asserted half", self.Key)
					}
					if self.IsPriced() {
						return fmt.Errorf("%s is priced; a self-asserted value must disclose free", self.Key)
					}
					if !gov.IsGovVerified() || !gov.IsPriced() {
						return fmt.Errorf("%s must be government-verified and priced", gov.Key)
					}
					// certifiedField is optional: a government key may be the
					// certified reading of an existing field (given_name_id
					// certifies given_name, and they share one registry row),
					// or a document field in its own right (the passport
					// portrait is not a certified avatar, and bills as its own
					// row). What must never happen is a dangling name.
					if gov.CertifiedField != "" {
						if _, ok := e.Ref.ByKey[gov.CertifiedField]; !ok {
							return fmt.Errorf("%s certifies %q, which is not in the referential",
								gov.Key, gov.CertifiedField)
						}
					}
				}
				return nil
			},
		},
		{
			Name: "every priced attribute names the row the enclave meters",
			Why:  "the marketplace key is what a reservation is made against; a key with no row fails the whole authorization, and a key pointing at the wrong row bills one disclosure as another",
			Run: func(e *Env) error {
				priced := e.Ref.Priced()
				if len(priced) == 0 {
					return fmt.Errorf("referential prices nothing")
				}
				if !e.marketplaceProvisioned() {
					return skip("this control plane carries no `privasys` attribute provider, so nothing here is buyable")
				}
				c, err := e.client("pricedrows", keysOf(priced))
				if err != nil {
					return err
				}
				for _, a := range priced {
					if !strings.HasPrefix(a.Marketplace.Key, "privasys:") {
						return fmt.Errorf("%s meters against %q, which is not namespaced",
							a.Key, a.Marketplace.Key)
					}
					q, err := e.Platform.QuoteAttributes(c.ClientID, []string{a.Marketplace.Key})
					if err != nil {
						return fmt.Errorf("%s meters against %s, which the registry will not price: %w",
							a.Key, a.Marketplace.Key, err)
					}
					if q.TotalCredits <= 0 {
						return fmt.Errorf("%s priced at %d credits", a.Key, q.TotalCredits)
					}
				}
				return nil
			},
		},
		{
			Name: "a self-asserted attribute arrives, free, in the token",
			Why:  "the free tier is the one most relying parties actually use; it is also the only tier this suite can drive end to end, so if it breaks silently nothing else here would notice",
			Run: func(e *Env) error {
				c, err := e.confidentialClient("selfasserted", []string{"email", "name"})
				if err != nil {
					return err
				}
				res, err := e.IdP.SignIn(e.Identity, SignInRequest{
					ClientID: c.ClientID, ClientSecret: c.ClientSecret,
					RedirectURI: e.Redirect, Scope: "openid email profile",
					Deliver: map[string]string{"email": qaEmail, "name": qaDisplayName},
				})
				if err != nil {
					return err
				}
				if got, _ := res.IDTokenClaims["email"].(string); got != qaEmail {
					return fmt.Errorf("email claim = %q, want %q", got, qaEmail)
				}
				if got, _ := res.IDTokenClaims["name"].(string); got != qaDisplayName {
					return fmt.Errorf("name claim = %q, want %q", got, qaDisplayName)
				}
				return nil
			},
		},
		{
			Name: "the token carries nothing the whitelist did not name",
			Why:  "the ceiling has to hold at the token endpoint too, not only at the point where the wallet is told what to collect — otherwise a value the wallet volunteered would reach a relying party that never registered for it",
			Run: func(e *Env) error {
				c, err := e.confidentialClient("tokenfilter", []string{"email"})
				if err != nil {
					return err
				}
				res, err := e.IdP.SignIn(e.Identity, SignInRequest{
					ClientID: c.ClientID, ClientSecret: c.ClientSecret,
					RedirectURI: e.Redirect, Scope: "openid email profile",
					// The wallet volunteers more than the client registered for.
					Deliver: map[string]string{
						"email": qaEmail, "name": qaDisplayName, "nickname": "qa",
					},
				})
				if err != nil {
					return err
				}
				for _, leaked := range []string{"name", "nickname"} {
					if _, ok := res.IDTokenClaims[leaked]; ok {
						return fmt.Errorf("%s reached a client whose whitelist is [email]", leaked)
					}
				}
				return nil
			},
		},
		{
			Name: "an unknown attribute is dropped, not fatal",
			Why:  "the request parameter is filled from a referential the relying party fetched itself, which may be newer than the IdP; a sign-in that fails outright is a worse answer than one missing a key the client can see is absent",
			Run: func(e *Env) error {
				c, err := e.client("unknown", []string{"email"})
				if err != nil {
					return err
				}
				auth, _, err := e.IdP.Authorize(SignInRequest{
					ClientID: c.ClientID, RedirectURI: e.Redirect,
					Scope:      "openid email",
					Attributes: []string{"email", "no_such_attribute_" + randHex(3)},
				})
				if err != nil {
					return fmt.Errorf("an unknown attribute failed the authorization: %w", err)
				}
				if !contains(auth.RequestedAttributes, "email") {
					return fmt.Errorf("the known attribute was lost alongside the unknown one")
				}
				return nil
			},
		},
		{
			Name: "the registry prices the set the inviter chose",
			Why:  "an inviter may require any attributes, not a fixed three, so the price has to be computed from the live registry; a client-side guess would drift the moment a price changed",
			Run: func(e *Env) error {
				priced := e.Ref.Priced()
				if len(priced) < 2 {
					return fmt.Errorf("referential prices fewer than two attributes")
				}
				if !e.marketplaceProvisioned() {
					return skip("this control plane carries no `privasys` attribute provider, so nothing here is buyable")
				}
				chosen := []string{priced[0].Marketplace.Key, priced[1].Marketplace.Key}
				c, err := e.client("quote", []string{priced[0].Key, priced[1].Key})
				if err != nil {
					return err
				}
				q, err := e.Platform.QuoteAttributes(c.ClientID, chosen)
				if err != nil {
					return err
				}
				if q.TotalCredits <= 0 {
					return fmt.Errorf("quote for %v totalled %d credits", chosen, q.TotalCredits)
				}
				var sum int64
				for _, a := range q.Attributes {
					sum += a.PriceCredits
				}
				if sum != q.TotalCredits {
					return fmt.Errorf("quote breakdown sums to %d but the total says %d", sum, q.TotalCredits)
				}
				return nil
			},
		},
		{
			Name: "a billing grant is priced against the registry, not the caller's claim",
			Why:  "the grant is what lets an inviter pay for a stranger's disclosure; if a caller could set its own ceiling below the real price, the disclosure would happen and the payment would not",
			Run: func(e *Env) error {
				priced := e.Ref.Priced()
				if len(priced) == 0 {
					return fmt.Errorf("referential prices nothing")
				}
				if !e.marketplaceProvisioned() {
					return skip("this control plane carries no `privasys` attribute provider, so nothing here is buyable")
				}
				attr := priced[0]
				c, err := e.client("grant", []string{attr.Key})
				if err != nil {
					return err
				}
				_, err = e.Platform.CreateBillingGrant(c.ClientID, []string{attr.Marketplace.Key}, 1)
				if got := statusOf(err); got != http.StatusBadRequest {
					return fmt.Errorf("a 1-credit ceiling on %s returned %s, want 400", attr.Key, describeErr(err))
				}
				return nil
			},
		},
	}
}
