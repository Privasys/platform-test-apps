// Privasys test fixture: container-app-dependency-provider (app B).
//
// A minimal confidential service that stands in for a dependency such as a
// Confidential AI enclave. It boots ready and exposes a tiny "inference"
// endpoint. Another app (container-app-dependency-consumer) depends on this one
// and will only call it after verifying, over RA-TLS, that this exact enclave
// identity is in its pinned attested-dependency set.
//
// The platform terminates RA-TLS in front of the container and stamps this app's
// identity (measurement + OID 3.6 app-id + OID 3.2 code hash + OID 65230.6.1
// dependency set) into the served certificate. The container itself serves plain
// HTTP on the injected $PORT.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const appVersion = "1.0.0"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is required")
	}
	name := os.Getenv("PRIVASYS_CONTAINER_NAME")

	mux := http.NewServeMux()

	// Liveness — the manager's readiness probe hits this.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"version": appVersion})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, 200, map[string]any{
			"app":     "container-app-dependency-provider",
			"name":    name,
			"version": appVersion,
			"role":    "attested dependency (provider)",
		})
	})

	// A stand-in "inference" call the consumer invokes once the dependency is
	// verified. Echoes the prompt so the e2e can assert the call succeeded.
	mux.HandleFunc("/infer", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// Echo the attested-caller identity the runtime injected on the ingress
		// mutual-RA-TLS path, so the e2e can assert the callee verified the
		// caller (X-Privasys-Peer-* set only after a successful verification;
		// the app itself can never forge them — the runtime strips inbound ones).
		caller := map[string]string{}
		for _, h := range []string{
			"X-Privasys-Peer-Verified", "X-Privasys-Peer-App-Id",
			"X-Privasys-Peer-Image-Digest", "X-Privasys-Peer-Measurement",
		} {
			if v := r.Header.Get(h); v != "" {
				caller[h] = v
			}
		}
		writeJSON(w, 200, map[string]any{
			"completion": "provider processed: " + strings.TrimSpace(body.Prompt),
			"version":    appVersion,
			"caller":     caller,
		})
	})

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("dependency-provider %s listening on %s", name, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
