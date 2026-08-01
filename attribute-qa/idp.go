// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// The OIDC leg: drive a real authorization at the real IdP and report exactly
// what came back.
//
// Nothing here is a mock. The QA harness is only useful if it exercises the
// deployed IdP, so every assertion in suite.go is a statement about production
// behaviour rather than about a fixture.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func esc(s string) string { return url.QueryEscape(s) }

// IdPClient talks to one Privasys IdP.
type IdPClient struct {
	Issuer string // e.g. https://privasys.id
	RPID   string // the WebAuthn RP id — the issuer's hostname
	HTTP   *http.Client
}

func NewIdPClient(issuer string) *IdPClient {
	issuer = strings.TrimRight(issuer, "/")
	host := issuer
	if u, err := url.Parse(issuer); err == nil {
		host = u.Hostname()
	}
	return &IdPClient{
		Issuer: issuer,
		RPID:   host,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *IdPClient) postJSON(path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.Issuer+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *IdPClient) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.Issuer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *IdPClient) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
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

// httpError carries the status so a test can assert on a refusal rather than
// only on a success. A QA tool that can only observe happy paths is half a
// tool: most of what this suite pins is what the platform REFUSES to do.
type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Body) }

func statusOf(err error) int {
	if he, ok := err.(*httpError); ok {
		return he.Status
	}
	return 0
}

// SignInRequest is one authorization: who is asking, for what, and as whom.
type SignInRequest struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scope        string
	// Attributes named on the request. Naming is the only way to reach a
	// request-only key (every government-backed `_id` attribute is one).
	Attributes []string
	ACRValues  string
	// BillingGrant, when set, is the inviter-pays grant the relying party
	// created so the recipient's disclosure is charged to somebody else.
	BillingGrant string
	// Deliver is what the wallet would hand over. Self-asserted values only:
	// see wallet.go.
	Deliver map[string]string
}

// SignInResult is what the relying party actually received.
type SignInResult struct {
	IDTokenClaims map[string]any    `json:"id_token_claims"`
	AccessToken   string            `json:"-"`
	ACR           string            `json:"acr"`
	// Requested is what the IdP told the wallet to collect — the intersection
	// of scope, named attributes and the client's whitelist ceiling.
	Requested    []string                        `json:"requested"`
	Requirements map[string]AttributeRequirement `json:"requirements"`
}

// AttributeRequirement mirrors the IdP's per-attribute demand.
type AttributeRequirement struct {
	Essential bool   `json:"essential"`
	Assurance string `json:"assurance"`
}

// authorizeResponse is the SDK-facing shape of /authorize.
//
// Note the spelling: the HTTP body uses snake_case, while the base64 QR payload
// carried inside it uses camelCase for the same two fields. Reading the wrong
// one yields an empty list and no error, which turns every "this attribute was
// NOT requested" assertion into a vacuous pass — the failure mode that hid
// behind five green cases on the first run of this suite.
type authorizeResponse struct {
	SessionID             string                          `json:"session_id"`
	RequestedAttributes   []string                        `json:"requested_attributes"`
	AttributeRequirements map[string]AttributeRequirement `json:"attribute_requirements"`
}

type sessionStatus struct {
	Authenticated bool   `json:"authenticated"`
	RedirectURI   string `json:"redirect_uri"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// AuthorizeURL builds one authorization request, returning the URL plus the
// PKCE verifier and state the caller must keep to finish it.
//
// Shared by both entry points on purpose: the browser console and the headless
// suite must send byte-identical requests, or the console stops being evidence
// about what the suite exercises.
func (c *IdPClient) AuthorizeURL(req SignInRequest) (target, verifier, state string) {
	verifierBytes := make([]byte, 32)
	rand.Read(verifierBytes)
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	state = randHex(16)

	q := url.Values{
		"client_id":             {req.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {req.Scope},
		"state":                 {state},
		"nonce":                 {randHex(16)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if len(req.Attributes) > 0 {
		q.Set("attributes", strings.Join(req.Attributes, " "))
	}
	if req.ACRValues != "" {
		q.Set("acr_values", req.ACRValues)
	}
	if req.BillingGrant != "" {
		q.Set("billing_grant", req.BillingGrant)
	}
	return c.Issuer + "/authorize?" + q.Encode(), verifier, state
}

// Authorize starts a sign-in and returns the session the wallet (or this
// harness standing in for it) must complete, along with what the IdP decided
// to ask the wallet for.
func (c *IdPClient) Authorize(req SignInRequest) (*authorizeResponse, string, error) {
	target, verifier, _ := c.AuthorizeURL(req)
	var out authorizeResponse
	if err := c.getJSON(strings.TrimPrefix(target, c.Issuer), &out); err != nil {
		return nil, "", fmt.Errorf("authorize: %w", err)
	}
	if out.SessionID == "" {
		return nil, "", fmt.Errorf("authorize returned no session_id")
	}
	return &out, verifier, nil
}

// ExchangeCode turns an authorization code into the relying party's ID token
// claims. Used by the console, where a browser (and a wallet approval) carried
// the ceremony and handed the code back on the redirect.
func (c *IdPClient) ExchangeCode(code, verifier string, client *OAuthClient, redirectURI string) (map[string]any, error) {
	tok, err := c.token(code, verifier, client.ClientID, client.ClientSecret, redirectURI)
	if err != nil {
		return nil, err
	}
	return decodeJWTClaims(tok.IDToken)
}

func (c *IdPClient) token(code, verifier, clientID, secret, redirectURI string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequest(http.MethodPost, c.Issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok tokenResponse
	if err := c.do(req, &tok); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	return &tok, nil
}

// SignIn runs a whole authorization to a token, standing in for both the
// authenticator and the wallet.
func (c *IdPClient) SignIn(id *Identity, req SignInRequest) (*SignInResult, error) {
	auth, verifier, err := c.Authorize(req)
	if err != nil {
		return nil, err
	}

	// Authenticate the session with the software passkey, enrolling on first
	// use and re-enrolling if the IdP has forgotten this credential.
	var cer *ceremonyResult
	if id.CredentialID == "" {
		cer, err = c.Register(id, auth.SessionID, qaDisplayName)
	} else {
		cer, err = c.Authenticate(id, auth.SessionID)
		if statusOf(err) == http.StatusNotFound {
			id.CredentialID = ""
			cer, err = c.Register(id, auth.SessionID, qaDisplayName)
		}
	}
	if err != nil {
		return nil, err
	}

	// Stand in for the wallet: deliver the attributes it would have collected.
	if err := c.CompleteSession(auth.SessionID, cer.UserID, req.Deliver); err != nil {
		return nil, err
	}

	var status sessionStatus
	if err := c.getJSON("/session/status?session_id="+esc(auth.SessionID), &status); err != nil {
		return nil, fmt.Errorf("session/status: %w", err)
	}
	if !status.Authenticated || status.RedirectURI == "" {
		return nil, fmt.Errorf("session did not authenticate")
	}
	redirect, err := url.Parse(status.RedirectURI)
	if err != nil {
		return nil, err
	}
	code := redirect.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("no code on %s", status.RedirectURI)
	}

	tok, err := c.token(code, verifier, req.ClientID, req.ClientSecret, req.RedirectURI)
	if err != nil {
		return nil, err
	}

	claims, err := decodeJWTClaims(tok.IDToken)
	if err != nil {
		return nil, err
	}
	acr, _ := claims["acr"].(string)
	return &SignInResult{
		IDTokenClaims: claims,
		AccessToken:   tok.AccessToken,
		ACR:           acr,
		Requested:     auth.RequestedAttributes,
		Requirements:  auth.AttributeRequirements,
	}, nil
}

// decodeJWTClaims reads the payload WITHOUT verifying the signature.
//
// Deliberate: this is an observation tool, and every claim it reports is one
// the IdP just minted over a channel the harness drove end to end. Verifying
// here would test the harness's copy of the JWKS, not the platform.
func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(raw, &claims)
}
