package depcheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// End-to-end enforcement test for attested cross-enclave dependencies.
//
// It builds a REAL X.509 certificate for the provider (app B) carrying the
// RA-TLS extensions the platform stamps — a TDX quote (MRTD), the app-id
// (OID 3.6), the code hash (OID 3.2), and B's own dependency set (OID 6.1) —
// then parses it exactly as the SDK would over the wire and drives the
// consumer's fail-closed enforcement. This exercises the full path: OID
// encoding -> certificate -> InspectCertificate -> VerifyPeerIsDependency.

func oid(dotted string) asn1.ObjectIdentifier {
	var out asn1.ObjectIdentifier
	for _, p := range strings.Split(dotted, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}

// providerCert builds a self-signed provider certificate with the given TDX
// MRTD, app-id, code hash, and (optional) advertised dependency set.
func providerCert(t *testing.T, mrtd []byte, appID, codeHash string, ownDeps ratls.DependencySet) *x509.Certificate {
	t.Helper()

	quote := make([]byte, ratls.TDXQuoteMinSize)
	copy(quote[ratls.TDXQuoteMRTDOff:ratls.TDXQuoteMRTDEnd], mrtd)

	exts := []pkix.Extension{
		{Id: oid(ratls.OidTDXQuote), Value: quote},
		{Id: oid(ratls.OidWorkloadAppID), Value: []byte(appID)},
		{Id: oid(ratls.OidWorkloadCodeHash), Value: []byte(codeHash)},
		{Id: oid(ratls.OidAttestedDependencySet), Value: ratls.EncodeDependencySet(ownDeps)},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "provider.enclave"},
		NotBefore:       time.Unix(0, 0).UTC(),
		NotAfter:        time.Unix(0, 0).UTC().AddDate(1, 0, 0),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mrtdBytes(b byte) []byte {
	m := make([]byte, 48)
	for i := range m {
		m[i] = b
	}
	return m
}

// pinnedSet is the consumer's pinned attested-dependency set: it depends on the
// provider app-id, pinned to a specific MRTD and code hash.
func pinnedSet(mrtd []byte, appID, codeHash string) ratls.DependencySet {
	return ratls.DependencySet{Entries: []ratls.DependencyEntry{{
		AppID:        appID,
		Measurements: []ratls.DepMeasurement{{TDX: &ratls.DepTdxMeasurement{MRTD: hex.EncodeToString(mrtd), RTMR1: "", RTMR2: ""}}},
		RequiredOids: []ratls.ExpectedOid{{OID: ratls.OidWorkloadCodeHash, ExpectedValue: []byte(codeHash)}},
	}}}
}

func TestE2E_AcceptsPinnedProvider(t *testing.T) {
	mrtd := mrtdBytes(0xB2)
	set := pinnedSet(mrtd, "provider-app", "provider-code-v1")
	cert := providerCert(t, mrtd, "provider-app", "provider-code-v1", ratls.DependencySet{})

	if err := VerifyPeer(cert, ratls.TeeTypeTDX, set); err != nil {
		t.Fatalf("expected the pinned provider to be accepted, got: %v", err)
	}
}

func TestE2E_FailsClosedOnRogueMeasurement(t *testing.T) {
	set := pinnedSet(mrtdBytes(0xB2), "provider-app", "provider-code-v1")
	// A provider with the right app-id but a DIFFERENT MRTD (rogue/compromised build).
	cert := providerCert(t, mrtdBytes(0xEE), "provider-app", "provider-code-v1", ratls.DependencySet{})

	if err := VerifyPeer(cert, ratls.TeeTypeTDX, set); err == nil {
		t.Fatal("expected fail-closed against a rogue provider measurement")
	}
}

func TestE2E_FailsClosedOnUndeclaredApp(t *testing.T) {
	set := pinnedSet(mrtdBytes(0xB2), "provider-app", "provider-code-v1")
	// A genuine enclave, but an app-id the consumer never declared as a dependency.
	cert := providerCert(t, mrtdBytes(0xB2), "some-other-app", "provider-code-v1", ratls.DependencySet{})

	if err := VerifyPeer(cert, ratls.TeeTypeTDX, set); err == nil {
		t.Fatal("expected fail-closed against an undeclared dependency app-id")
	}
}

func TestE2E_FailsClosedOnCodeHashMismatch(t *testing.T) {
	set := pinnedSet(mrtdBytes(0xB2), "provider-app", "provider-code-v1")
	// Right measurement + app-id, but the pinned OID 3.2 code hash differs.
	cert := providerCert(t, mrtdBytes(0xB2), "provider-app", "provider-code-v2", ratls.DependencySet{})

	if err := VerifyPeer(cert, ratls.TeeTypeTDX, set); err == nil {
		t.Fatal("expected fail-closed when the required code-hash OID does not match")
	}
}

// The provider advertises its OWN dependency set in OID 6.1. The consumer can
// read it back from the real certificate — proving the mint/parse contract holds
// through an actual X.509 round-trip (and enabling the wallet to walk provenance).
func TestE2E_AdvertisedDependencySetRoundTrips(t *testing.T) {
	ownDeps := ratls.DependencySet{Entries: []ratls.DependencyEntry{{
		AppID:          "vector-db",
		Measurements:   []ratls.DepMeasurement{{TDX: &ratls.DepTdxMeasurement{MRTD: hex.EncodeToString(mrtdBytes(0xCC)), RTMR1: "", RTMR2: ""}}},
		FoldedIdentity: hex.EncodeToString(make([]byte, 32)),
	}}}
	cert := providerCert(t, mrtdBytes(0xB2), "provider-app", "provider-code-v1", ownDeps)

	info := ratls.InspectCertificate(cert)
	var advertised []byte
	for _, o := range info.CustomOids {
		if o.OID == ratls.OidAttestedDependencySet {
			advertised = o.Value
		}
	}
	if advertised == nil {
		t.Fatal("provider certificate did not carry the OID 6.1 dependency set")
	}
	decoded, err := ratls.DecodeDependencySet(advertised)
	if err != nil {
		t.Fatalf("decode advertised dependency set: %v", err)
	}
	if len(decoded.Entries) != 1 || decoded.Entries[0].AppID != "vector-db" {
		b, _ := json.Marshal(decoded)
		t.Fatalf("unexpected advertised dependency set: %s", b)
	}
}
