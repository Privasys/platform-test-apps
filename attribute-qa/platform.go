// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// The management-service leg: register the relying parties a test needs, and
// exercise the money side (what a set of attributes costs, and who pays).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PlatformClient talks to one management-service.
type PlatformClient struct {
	BaseURL string
	Token   string // a platform bearer; see token.go for where it comes from
	HTTP    *http.Client
}

func NewPlatformClient(baseURL, token string) *PlatformClient {
	return &PlatformClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *PlatformClient) call(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, p.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return &httpError{Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// OAuthClient is a registered relying party.
type OAuthClient struct {
	ClientID           string   `json:"client_id"`
	ClientSecret       string   `json:"client_secret"`
	ClientName         string   `json:"client_name"`
	RPID               string   `json:"rp_id"`
	RequiredAttributes []string `json:"required_attributes"`
}

// RegisterClient creates a relying party with the given whitelist.
//
// The whitelist is a ceiling on everything that follows, and it is mandatory:
// a client that names nothing receives nothing. Several tests below register a
// deliberately narrow one and then try to escape it.
func (p *PlatformClient) RegisterClient(name string, redirectURIs, attrs []string, billable bool) (*OAuthClient, error) {
	var out OAuthClient
	err := p.call(http.MethodPost, "/api/v1/oauth-clients", map[string]any{
		"client_name":         name,
		"redirect_uris":       redirectURIs,
		"required_attributes": attrs,
		"billable_rp":         billable,
	}, &out)
	return &out, err
}

// ListClients returns the relying parties on the caller's account, so a QA run
// can reuse a client it registered earlier instead of minting a new one every
// time.
func (p *PlatformClient) ListClients() ([]OAuthClient, error) {
	var out []OAuthClient
	err := p.call(http.MethodGet, "/api/v1/oauth-clients", nil, &out)
	return out, err
}

// AttributeQuote is what a chosen set of attributes costs.
//
// The per-line field is `price_credits`, not `credits`: reading the wrong name
// yields a silent zero, which is why the suite cross-checks the breakdown
// against the total instead of trusting either on its own.
type AttributeQuote struct {
	TotalCredits int64 `json:"total_credits"`
	Attributes   []struct {
		Key          string `json:"key"`
		Assurance    string `json:"assurance"`
		PriceCredits int64  `json:"price_credits"`
	} `json:"attributes"`
}

// QuoteAttributes prices the set an inviter picked. The inviter is free to
// choose any attributes, so the price is always computed server-side from the
// live registry rather than assumed by the caller.
func (p *PlatformClient) QuoteAttributes(clientID string, keys []string) (*AttributeQuote, error) {
	var out AttributeQuote
	err := p.call(http.MethodPost, "/api/v1/attribute-billing-grants/quote", map[string]any{
		"client_id":  clientID,
		"attributes": keys,
	}, &out)
	return &out, err
}

// BillingGrant is a single-use authorisation for somebody else's disclosure to
// be charged to the caller — the inviter-pays primitive.
type BillingGrant struct {
	ID         string `json:"id"`
	MaxCredits int64  `json:"max_credits"`
	ExpiresAt  string `json:"expires_at"`
}

// CreateBillingGrant authorises one recipient's disclosure at the caller's
// expense. The payer is always resolved from the bearer, never from the body,
// so an app can never nominate somebody else to pay.
func (p *PlatformClient) CreateBillingGrant(clientID string, keys []string, maxCredits int64) (*BillingGrant, error) {
	body := map[string]any{
		"client_id":  clientID,
		"attributes": keys,
	}
	if maxCredits > 0 {
		body["max_credits"] = maxCredits
	}
	var out BillingGrant
	err := p.call(http.MethodPost, "/api/v1/attribute-billing-grants", body, &out)
	return &out, err
}

// Balance reads the caller's credit balance, so a test can assert that a
// disclosure moved exactly what the quote said it would.
func (p *PlatformClient) Balance() (int64, error) {
	var out struct {
		Balance int64 `json:"balance"`
		Credits int64 `json:"credits"`
	}
	if err := p.call(http.MethodGet, "/api/v1/billing/balance", nil, &out); err != nil {
		return 0, err
	}
	if out.Balance != 0 {
		return out.Balance, nil
	}
	return out.Credits, nil
}

func describeErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%v", err)
}
