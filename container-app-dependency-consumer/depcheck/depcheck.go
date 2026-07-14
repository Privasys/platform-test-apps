// Package depcheck is the attested-dependency enforcement the consumer runs
// before it will talk to a dependency enclave. It is a thin, fail-closed wrapper
// over the RA-TLS SDK: parse the peer's certificate, then require the peer to
// match the identity this app has pinned for that dependency. If the peer is not
// a declared dependency, or its measurement / required OIDs do not match, the
// call fails and no application data is sent.
package depcheck

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"enclave-os-mini/clients/go/ratls"
)

// EnvPinnedDependencies is the env var the platform injects with this app's
// pinned attested-dependency set (the same set the runtime seals into OID
// 65230.6.1). It is a JSON dependency set: {"entries":[...]} or a bare [...].
const EnvPinnedDependencies = "PRIVASYS_ATTESTED_DEPENDENCIES"

// LoadPinnedSet reads the pinned dependency set from EnvPinnedDependencies. An
// unset/empty var yields an empty set (the app declares no dependencies, so any
// attempt to treat a peer as a dependency fails closed).
func LoadPinnedSet() (ratls.DependencySet, error) {
	return ParsePinnedSet(os.Getenv(EnvPinnedDependencies))
}

// ParsePinnedSet parses a dependency set from JSON (accepts {"entries":[...]} or
// a bare array).
func ParsePinnedSet(raw string) (ratls.DependencySet, error) {
	if raw == "" {
		return ratls.DependencySet{}, nil
	}
	var set ratls.DependencySet
	if err := json.Unmarshal([]byte(raw), &set); err == nil && set.Entries != nil {
		return set, nil
	}
	var entries []ratls.DependencyEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return ratls.DependencySet{}, fmt.Errorf("parse pinned dependency set: %w", err)
	}
	return ratls.DependencySet{Entries: entries}, nil
}

// VerifyPeer enforces, fail-closed, that peerCert belongs to a pinned dependency.
// It parses the certificate's RA-TLS extensions and delegates to the SDK's
// VerifyPeerIsDependency, which selects the pinned entry by the peer's app-id
// (OID 65230.3.6) and requires a measurement + required-OID match. Returns nil
// only when the peer is a declared, matching dependency.
func VerifyPeer(peerCert *x509.Certificate, tee ratls.TeeType, set ratls.DependencySet) error {
	info := ratls.InspectCertificate(peerCert)
	return ratls.VerifyPeerIsDependency(info, tee, set)
}
