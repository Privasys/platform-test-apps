// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command attribute-qa exercises the Privasys attribute model against a real
// deployment.
//
//	attribute-qa test    headless assertions, exit 0/1, --json for a report
//	attribute-qa serve   a browser console for the tiers a wallet must approve
//
// It defaults to the dev control plane. A full run against prod bills every
// government-backed disclosure at its real price, so pointing it there is an
// explicit choice (--prod).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	devEndpoint   = "https://api-test.developer.privasys.org"
	prodEndpoint  = "https://api.developer.privasys.org"
	defaultIssuer = "https://privasys.id"

	qaDisplayName = "Attribute QA"
	qaEmail       = "attribute-qa@test.privasys.org"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "test":
		err = runTest(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "attribute-qa: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `attribute-qa — QA harness for the Privasys attribute model

  attribute-qa test  [flags]   run the headless suite (exit 0 = all passed)
  attribute-qa serve [flags]   browser console for wallet-approved tiers

Common flags:
  --prod            target the production control plane (default: dev)
  --endpoint URL    management-service base URL (overrides --prod)
  --issuer URL      IdP issuer (default `+defaultIssuer+`)
  --token TOKEN     platform bearer (default: the privasys CLI's stored token)
  --identity PATH   where the software passkey is persisted

test flags:
  --json            emit a machine-readable report on stdout
  --run SUBSTRING   only cases whose name contains SUBSTRING

serve flags:
  --port N          console port (default 8099)
`)
}

type commonFlags struct {
	endpoint      string
	issuer        string
	token         string
	identity      string
	idpAdminToken string
	prod          bool
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.BoolVar(&c.prod, "prod", false, "target production")
	fs.StringVar(&c.endpoint, "endpoint", "", "management-service base URL")
	fs.StringVar(&c.issuer, "issuer", defaultIssuer, "IdP issuer")
	fs.StringVar(&c.token, "token", "", "platform bearer token")
	fs.StringVar(&c.identity, "identity", defaultIdentityPath(), "software passkey file")
	// Only `serve` needs this: registering a PUBLIC relying party per
	// selection is an IdP admin operation, and the management-service always
	// mints a secret (which a browser flow cannot use).
	fs.StringVar(&c.idpAdminToken, "idp-admin-token", os.Getenv("IDP_ADMIN_TOKEN"),
		"IdP admin token (serve only; defaults to $IDP_ADMIN_TOKEN)")
	return c
}

// resolve settles the endpoint after parsing, so an explicit --endpoint always
// wins over the --prod shorthand.
func (c *commonFlags) resolve() {
	if c.endpoint != "" {
		return
	}
	c.endpoint = devEndpoint
	if c.prod {
		c.endpoint = prodEndpoint
	}
}

func defaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".attribute-qa-identity.json"
	}
	return filepath.Join(home, ".privasys", "attribute-qa-identity.json")
}

// platformToken finds a bearer: the flag, then the environment, then the
// privasys CLI's own credential store. Shelling out to the CLI keeps this tool
// free of the refresh and keychain logic that already exists there.
//
// The stored access token is short-lived and `auth list` reports it verbatim,
// expired or not. So make a cheap authenticated call first: that is what drives
// the CLI's refresh, and reading afterwards yields a token that will still be
// valid when the suite uses it. Skipping this produced a run where all ten
// cases "failed" on 401 and none of them had actually been exercised.
func platformToken(flagValue, endpoint string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if t := os.Getenv("PRIVASYS_TOKEN"); t != "" {
		return t, nil
	}
	refresh := exec.Command("privasys", "account", "show", "--endpoint", endpoint, "--format", "json")
	refresh.Stdout, refresh.Stderr = nil, nil
	_ = refresh.Run()

	out, err := exec.Command("privasys", "auth", "list", "--format", "json").Output()
	if err != nil {
		return "", fmt.Errorf("no --token given and the privasys CLI could not supply one: %w", err)
	}
	var creds []struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(out, &creds); err != nil || len(creds) == 0 || creds[0].AccessToken == "" {
		return "", fmt.Errorf("no --token given and the privasys CLI has no stored credential (run: privasys auth login)")
	}
	return creds[0].AccessToken, nil
}

func newEnv(c *commonFlags, redirect string) (*Env, error) {
	token, err := platformToken(c.token, c.endpoint)
	if err != nil {
		return nil, err
	}
	idp := NewIdPClient(c.issuer)
	ref, err := LoadReferential(idp)
	if err != nil {
		return nil, err
	}
	identity, err := LoadOrCreateIdentity(c.identity)
	if err != nil {
		return nil, err
	}
	return &Env{
		IdP:      idp,
		Platform: NewPlatformClient(c.endpoint, token),
		Ref:      ref,
		Identity: identity,
		Redirect: redirect,
	}, nil
}

// ── test ──────────────────────────────────────────────────────────────────

type caseReport struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Skipped  bool   `json:"skipped,omitempty"`
	Error    string `json:"error,omitempty"`
	Why      string `json:"why"`
	Duration string `json:"duration"`
}

func runTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	common := bindCommon(fs)
	asJSON := fs.Bool("json", false, "machine-readable report")
	only := fs.String("run", "", "only cases containing this substring")
	if err := fs.Parse(args); err != nil {
		return err
	}
	common.resolve()

	// The suite never completes a redirect in a browser; it reads the code off
	// the session directly. The URI only has to be one the client registered.
	env, err := newEnv(common, "http://localhost:8099/callback")
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "attribute-qa: %s via %s (%d attributes in the referential)\n",
		common.endpoint, common.issuer, len(env.Ref.Attributes))

	var reports []caseReport
	failed, skipped := 0, 0
	for _, c := range Cases() {
		if *only != "" && !strings.Contains(c.Name, *only) {
			continue
		}
		start := time.Now()
		err := c.Run(env)
		rep := caseReport{
			Name: c.Name, Passed: err == nil, Why: c.Why,
			Duration: time.Since(start).Round(time.Millisecond).String(),
		}
		mark := "ok  "
		switch {
		case err == nil:
		case isSkip(err):
			rep.Skipped, rep.Error = true, err.Error()
			skipped++
			mark = "skip"
		default:
			rep.Error = err.Error()
			failed++
			mark = "FAIL"
		}
		reports = append(reports, rep)
		if !*asJSON {
			fmt.Printf("%s  %s (%s)\n", mark, c.Name, rep.Duration)
			switch {
			case isSkip(err):
				fmt.Printf("      %v\n", err)
			case err != nil:
				fmt.Printf("      %v\n      why it matters: %s\n", err, c.Why)
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"endpoint": common.endpoint,
			"issuer":   common.issuer,
			"passed":   len(reports) - failed - skipped,
			"failed":   failed,
			"skipped":  skipped,
			"cases":    reports,
		}); err != nil {
			return err
		}
	} else {
		fmt.Printf("\n%d passed, %d failed, %d skipped\n",
			len(reports)-failed-skipped, failed, skipped)
		fmt.Println("\nGovernment-backed tiers are not covered here: they need a real wallet")
		fmt.Println("holding a real document. Run `attribute-qa serve` for those.")
	}
	if failed > 0 {
		return fmt.Errorf("%d case(s) failed", failed)
	}
	return nil
}
