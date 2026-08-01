// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// A software FIDO2 authenticator, so the QA suite can sign in without a phone.
//
// This is the same trick the portal's Playwright suite uses (websites
// e2e/lib/fido2-client.ts), ported to Go: a P-256 key pair standing in for a
// platform authenticator, producing the WebAuthn structures the IdP's
// go-webauthn verifier expects. It proves possession of a key the IdP
// registered, which is exactly what a real passkey proves — the credential is
// software-held rather than hardware-held, and nothing here weakens the
// server's check.
//
// It cannot stand in for the WALLET, which is a separate matter entirely: see
// wallet.go for what a test identity can and cannot assert.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// A fixed AAGUID marking credentials minted by this harness. Real
// authenticators carry a vendor id here; a distinct constant makes QA
// credentials obvious in the IdP's credential table.
var qaAAGUID = []byte{
	0x9a, 0x71, 0x00, 0x1e, 0x11, 0x00, 0x4b, 0x1e,
	0x00, 0x00, 0x51, 0x51, 0x00, 0x00, 0x00, 0x00,
}

// Identity is one persisted test user: a key pair plus what the IdP called it.
//
// It is written to disk and reused because the IdP keys role grants and
// disclosure history to the user id. A fresh key every run would produce a new
// user every run, and assertions about what a returning user sees could never
// be written.
type Identity struct {
	PrivateKeyD  string `json:"private_key_d"` // base64url of the P-256 scalar
	UserHandle   string `json:"user_handle"`
	CredentialID string `json:"credential_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`

	key *ecdsa.PrivateKey
	path string
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// LoadOrCreateIdentity reads the persisted identity, minting one on first use.
func LoadOrCreateIdentity(path string) (*Identity, error) {
	id := &Identity{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, id); err != nil {
			return nil, fmt.Errorf("identity file %s: %w", path, err)
		}
		d, err := b64uDecode(id.PrivateKeyD)
		if err != nil {
			return nil, fmt.Errorf("identity file %s: bad key: %w", path, err)
		}
		id.key = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
		id.key.D = new(big.Int).SetBytes(d)
		id.key.PublicKey.X, id.key.PublicKey.Y = elliptic.P256().ScalarBaseMult(d)
		id.path = path
		return id, nil
	case !os.IsNotExist(err):
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	handle := make([]byte, 16)
	if _, err := rand.Read(handle); err != nil {
		return nil, err
	}
	id.key = key
	id.PrivateKeyD = b64u(key.D.FillBytes(make([]byte, 32)))
	id.UserHandle = b64u(handle)
	return id, id.Save()
}

// Save persists the identity, creating the directory on first write.
func (i *Identity) Save() error {
	if err := os.MkdirAll(filepath.Dir(i.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(i.path, raw, 0o600)
}

func (i *Identity) coords() (x, y []byte) {
	return i.key.PublicKey.X.FillBytes(make([]byte, 32)), i.key.PublicKey.Y.FillBytes(make([]byte, 32))
}

// credentialID derives a stable credential id from the public key, so a
// re-registration after a wiped IdP database lands on the same id.
func (i *Identity) credentialID() []byte {
	x, y := i.coords()
	sum := sha256.Sum256(append(append([]byte{}, x...), y...))
	return sum[:]
}

// ── Minimal CBOR, enough for a COSE key and an fmt="none" attestation ──────
//
// Hand-rolled rather than pulled from a library: the encoder needs to emit
// exactly four shapes, and a test fixture that depends on nothing is one that
// still builds in five years.

func cborUint(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborBytes(b []byte) []byte    { return append(cborUint(2, uint64(len(b))), b...) }
func cborText(s string) []byte     { return append(cborUint(3, uint64(len(s))), s...) }
func cborMapHeader(n int) []byte   { return cborUint(5, uint64(n)) }
func cborNegInt(v int64) []byte    { return cborUint(1, uint64(-v-1)) }
func cborPosInt(v int64) []byte    { return cborUint(0, uint64(v)) }

// coseKey encodes the P-256 public key as COSE_Key (ES256), the format
// WebAuthn carries inside attested credential data.
func coseKey(x, y []byte) []byte {
	out := cborMapHeader(5)
	out = append(out, cborPosInt(1)...)      // kty
	out = append(out, cborPosInt(2)...)      //   EC2
	out = append(out, cborPosInt(3)...)      // alg
	out = append(out, cborNegInt(-7)...)     //   ES256
	out = append(out, cborNegInt(-1)...)     // crv
	out = append(out, cborPosInt(1)...)      //   P-256
	out = append(out, cborNegInt(-2)...)     // x
	out = append(out, cborBytes(x)...)
	out = append(out, cborNegInt(-3)...)     // y
	out = append(out, cborBytes(y)...)
	return out
}

func attestationObject(authData []byte) []byte {
	out := cborMapHeader(3)
	out = append(out, cborText("fmt")...)
	out = append(out, cborText("none")...)
	out = append(out, cborText("attStmt")...)
	out = append(out, cborMapHeader(0)...)
	out = append(out, cborText("authData")...)
	out = append(out, cborBytes(authData)...)
	return out
}

func clientDataJSON(typ, challenge, origin string) []byte {
	// Field order matters only in that the server re-parses it as JSON; the
	// bytes are what gets signed, so build them once and reuse.
	raw, _ := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	return raw
}

type beginOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

type ceremonyResult struct {
	SessionToken   string `json:"sessionToken"`
	UserID         string `json:"userId"`
	RecoveryPhrase string `json:"recoveryPhrase,omitempty"`
}

// Register enrols the software credential, binding it to an in-flight OIDC
// session when sessionID is non-empty.
func (c *IdPClient) Register(id *Identity, sessionID, displayName string) (*ceremonyResult, error) {
	var begin beginOptions
	if err := c.postJSON("/fido2/register/begin?session_id="+esc(sessionID), map[string]any{
		"userName":   displayName,
		"userHandle": id.UserHandle,
	}, &begin); err != nil {
		return nil, fmt.Errorf("register/begin: %w", err)
	}

	x, y := id.coords()
	credID := id.credentialID()
	attested := append(append([]byte{}, qaAAGUID...),
		byte(len(credID)>>8), byte(len(credID)))
	attested = append(attested, credID...)
	attested = append(attested, coseKey(x, y)...)

	rpHash := sha256.Sum256([]byte(c.RPID))
	// UP | UV | AT — user present, user verified, attested credential included.
	authData := append(append([]byte{}, rpHash[:]...), 0x45, 0, 0, 0, 0)
	authData = append(authData, attested...)

	clientData := clientDataJSON("webauthn.create", begin.PublicKey.Challenge, "https://"+c.RPID)
	credB64 := b64u(credID)

	var out ceremonyResult
	if err := c.postJSON("/fido2/register/complete?challenge="+esc(begin.PublicKey.Challenge), map[string]any{
		"id": credB64, "rawId": credB64, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(clientData),
			"attestationObject": b64u(attestationObject(authData)),
		},
	}, &out); err != nil {
		return nil, fmt.Errorf("register/complete: %w", err)
	}
	id.CredentialID, id.UserID = credB64, out.UserID
	return &out, id.Save()
}

// Authenticate asserts the existing credential against an OIDC session.
func (c *IdPClient) Authenticate(id *Identity, sessionID string) (*ceremonyResult, error) {
	var begin beginOptions
	if err := c.postJSON("/fido2/authenticate/begin?session_id="+esc(sessionID), map[string]any{
		"credentialId": id.CredentialID,
	}, &begin); err != nil {
		return nil, fmt.Errorf("authenticate/begin: %w", err)
	}

	rpHash := sha256.Sum256([]byte(c.RPID))
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0) // UP | UV
	clientData := clientDataJSON("webauthn.get", begin.PublicKey.Challenge, "https://"+c.RPID)
	clientHash := sha256.Sum256(clientData)

	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		return nil, err
	}

	var out ceremonyResult
	if err := c.postJSON("/fido2/authenticate/complete?challenge="+esc(begin.PublicKey.Challenge), map[string]any{
		"id": id.CredentialID, "rawId": id.CredentialID, "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(clientData),
			"authenticatorData": b64u(authData),
			"signature":         b64u(sig),
		},
	}, &out); err != nil {
		return nil, fmt.Errorf("authenticate/complete: %w", err)
	}
	return &out, nil
}
