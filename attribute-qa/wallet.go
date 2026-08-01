// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// Standing in for the wallet — and the exact line where that stops working.
//
// Attributes reach the IdP one way: the wallet POSTs them to /session/complete
// once it has authenticated the session. A FIDO2 ceremony on its own carries
// none, so a harness that wants to assert anything about attributes has to
// play the wallet's part of the protocol. That is what this file does.
//
// It can only ever deliver SELF-ASSERTED values. A government-backed attribute
// is not a string, it is an SD-JWT disclosure signed by the identity-verifier
// enclave after it read a passport chip and matched a live face. There is no
// software stand-in for that, and building one would mean building a forgery
// path into a QA tool — a bypass with a friendly name. Government-tier
// assertions therefore run against a real wallet holding a real credential,
// which is what `attribute-qa serve` is for.

import "fmt"

// CompleteSession delivers what the wallet would have collected.
//
// Values must be self-asserted. Passing a key the referential marks
// government-verified is refused here rather than sent, because the IdP would
// accept the string and the relying party would receive a raw value where a
// disclosure token belongs — a test that passes for the wrong reason.
func (c *IdPClient) CompleteSession(sessionID, userID string, attrs map[string]string) error {
	body := map[string]any{
		"session_id": sessionID,
		"user_id":    userID,
	}
	if len(attrs) > 0 {
		body["attributes"] = attrs
	}
	return c.postJSON("/session/complete", body, nil)
}

// GovTierUnsupported explains why a set cannot be driven headlessly, or
// returns nil when every key is self-assertable.
func GovTierUnsupported(ref *Referential, keys []string) error {
	var gov []string
	for _, k := range keys {
		if a, ok := ref.ByKey[k]; ok && a.IsGovVerified() {
			gov = append(gov, k)
		}
	}
	if len(gov) == 0 {
		return nil
	}
	return fmt.Errorf("government-backed attributes need a real wallet and a real document: %v", gov)
}
