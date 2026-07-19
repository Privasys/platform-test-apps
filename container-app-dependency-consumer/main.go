// Privasys test fixture: container-app-dependency-consumer (app A).
//
// A confidential service that depends on container-app-dependency-provider
// (app B). When asked, it opens an RA-TLS connection to the provider and — before
// sending any application data — enforces, fail-closed, that the provider's
// enclave identity is in this app's pinned attested-dependency set (the same set
// the runtime seals into certificate extension OID 1.3.6.1.4.1.65230.6.1). Only
// then does it call the provider's /infer endpoint.
//
// Two independent checks run on the peer:
//  1. Ordinary RA-TLS verification (challenge-bound quote + report-data), so the
//     certificate is a genuine, freshly-attested enclave bound to this session.
//  2. The dependency pin (depcheck): the peer must match the identity pinned for
//     its app-id. A genuine-but-undeclared enclave is refused.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"enclave-os-mini/clients/go/ratls"

	"container-app-dependency-consumer/depcheck"
)

const appVersion = "1.0.0"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"version": appVersion})
	})
	mux.HandleFunc("/ask", handleAsk)

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("dependency-consumer listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// handleAsk connects to the provider, verifies it is a pinned dependency, then
// forwards the prompt to the provider's /infer.
func handleAsk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Prompt string `json:"prompt"`
		// ProviderURL lets the caller name the provider at call time (host or
		// host:port). Falls back to the PROVIDER_URL env var. This keeps the
		// fixture usable on the container-app deploy path, which does not inject
		// custom env vars.
		ProviderURL string `json:"provider_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	host, portNum, err := providerHostPort(body.ProviderURL)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// Egress dependency pin (OID 6.1). Optional: when the runtime injects no
	// pinned set (PRIVASYS_ATTESTED_DEPENDENCIES unset, e.g. an ingress-only
	// test), the egress dependency check is skipped so the ingress mutual-RA-TLS
	// leg (the provider verifying THIS caller) can be exercised on its own.
	pinned, err := depcheck.LoadPinnedSet()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	enforceEgress := len(pinned.Entries) > 0

	// Fresh challenge nonce so the provider mints a session-bound quote.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeJSON(w, 500, map[string]any{"error": "nonce"})
		return
	}
	opts := &ratls.Options{
		ServerName: host,
		Challenge:  nonce,
	}
	// Ingress mutual RA-TLS: present this container's attested client identity so
	// a provider that pins allowed-callers can verify us. The measured manager
	// mints the cert bound to this session's channel binder. Skipped only if the
	// manager URL is not injected (then the provider must not require a caller).
	if mgrURL := os.Getenv("PRIVASYS_MANAGER_URL"); mgrURL != "" {
		if _, getCert, cerr := ratls.EgressClientCert(mgrURL, os.Getenv("PRIVASYS_CONTAINER_TOKEN")); cerr == nil {
			opts.GetClientCertificate = getCert
		} else {
			log.Printf("egress client identity unavailable: %v", cerr)
		}
	}
	client, err := ratls.Connect(host, portNum, opts)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "connect provider: " + err.Error()})
		return
	}
	defer client.Close()

	certs := client.PeerCertificates()
	if len(certs) == 0 {
		writeJSON(w, 502, map[string]any{"error": "provider presented no certificate"})
		return
	}
	leaf := certs[0]

	if enforceEgress {
		// (1) Ordinary RA-TLS verification: challenge-bound quote + report-data,
		// plus the attestation server(s) confirm the raw quote. Fails closed on a
		// relayed or co-located quote that cannot commit to this TLS session.
		policy := &ratls.VerificationPolicy{
			TEE:        ratls.TeeTypeTDX,
			ReportData: ratls.ReportDataChallengeResponse,
			Nonce:      nonce,
		}
		if _, err := ratls.VerifyRaTlsCertBound(leaf, policy, client.ChannelBinder()); err != nil {
			writeJSON(w, 502, map[string]any{"error": "provider attestation failed: " + err.Error()})
			return
		}
		// (2) The dependency pin: the provider must be a declared dependency of
		// THIS app and match the pinned identity. Fail closed otherwise.
		if err := depcheck.VerifyPeer(leaf, ratls.TeeTypeTDX, pinned); err != nil {
			writeJSON(w, 403, map[string]any{"error": "provider is not a pinned dependency: " + err.Error()})
			return
		}
	}

	// Forward the prompt to the provider. On the ingress mutual-RA-TLS path the
	// provider's runtime verifies OUR presented client certificate and either
	// echoes our attested identity in X-Privasys-Peer-* (which the provider
	// returns under "caller") or rejects us with 403.
	reqBody, _ := json.Marshal(map[string]string{"prompt": body.Prompt})
	resp, err := client.HTTPDo(http.MethodPost, "/infer", host, reqBody, "")
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "provider call failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	var inferOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&inferOut)
	writeJSON(w, resp.StatusCode, map[string]any{
		"provider":        inferOut,
		"provider_status": resp.StatusCode,
		"egress_verified": enforceEgress,
	})
}

func providerHostPort(override string) (string, int, error) {
	url := override
	if url == "" {
		url = os.Getenv("PROVIDER_URL")
	}
	if url == "" {
		return "", 0, fmt.Errorf("provider_url (body) or PROVIDER_URL (env) is required")
	}
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	host, portStr, found := strings.Cut(url, ":")
	if !found {
		return host, 443, nil
	}
	p, err := strconv.Atoi(strings.TrimRight(portStr, "/"))
	if err != nil {
		return "", 0, fmt.Errorf("invalid PROVIDER_URL port")
	}
	return host, p, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
