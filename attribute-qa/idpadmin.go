// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// Registering the relying party a console selection actually describes.
//
// Two facts about the whitelist force this. First, it is a CEILING, so a client
// whitelisted for the whole referential asks for everything its scope reaches —
// which is why picking one attribute in the console made the wallet offer the
// lot. Second, for a request-only key the whitelist is also a form of NAMING
// (see the IdP's namedByRegistration): a government key sitting in the ceiling
// is requested as soon as the scope admits it, whether or not the request names
// it. A whitelist of everything is therefore a request for everything.
//
// So each selection gets its own relying party whose whitelist is exactly what
// was ticked. That is also what an honest QA tool should do: real relying
// parties register the attributes they need, and testing against a client that
// can ask for anything tests a configuration nobody ships.
//
// These are registered PUBLIC (no client secret) through the IdP's admin
// endpoint. The management-service always mints a secret, and a confidential
// client cannot complete the SDK's browser PKCE flow — /token verifies the
// secret unconditionally, and the browser has none to give.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// IdPAdmin registers clients directly at the IdP.
type IdPAdmin struct {
	Issuer string
	Token  string
	HTTP   *http.Client
}

func NewIdPAdmin(issuer, token string) *IdPAdmin {
	return &IdPAdmin{
		Issuer: strings.TrimRight(issuer, "/"),
		Token:  token,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

// EnsurePublicClient upserts a public relying party whose whitelist is exactly
// `attrs`, and returns its client id.
//
// The id is derived from the attribute set, so the same selection always maps
// to the same client and repeated QA runs do not litter the registry. The
// upsert also means a changed selection rewrites that client's whitelist rather
// than leaving a stale ceiling behind.
func (a *IdPAdmin) EnsurePublicClient(redirectURI string, attrs []string) (string, error) {
	sorted := append([]string(nil), attrs...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ",")))
	clientID := "qa-console-" + hex.EncodeToString(sum[:6])

	body, err := json.Marshal(map[string]any{
		"client_id":           clientID,
		"client_name":         "Attribute QA (" + strings.Join(sorted, ", ") + ")",
		"redirect_uris":       []string{redirectURI},
		"required_attributes": sorted,
		// No client_secret: a public client, which is what a browser flow needs.
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.Issuer+"/clients", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)

	if err := a.post("/clients", body); err != nil {
		return "", fmt.Errorf("register %s: %w", clientID, err)
	}
	return clientID, nil
}

// MakeBillable links the client to the account that pays for its disclosures.
//
// Without this a government-backed attribute simply never arrives, and it looks
// like the wallet ignored the request. It doesn't: /authorize only mints a
// disclosure voucher for a BILLABLE relying party with a billing account, the
// verifier enclave refuses to issue a government credential without a voucher
// (REQUIRE_VOUCHER is baked into its measured image), and so the ceremony
// completes having disclosed nothing. That is the system being correct — no
// payment, no paid disclosure — but from the console it reads as silence.
//
// The consequence is real money: every government disclosure the console asks
// for is charged to this account at the registry's price.
func (a *IdPAdmin) MakeBillable(clientID, accountID string) error {
	body, err := json.Marshal(map[string]any{
		"billable_rp":        true,
		"billing_account_id": accountID,
		"rp_id":              clientID,
	})
	if err != nil {
		return err
	}
	return a.post("/clients/"+clientID+"/billing", body)
}

func (a *IdPAdmin) post(path string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, a.Issuer+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Token)

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
