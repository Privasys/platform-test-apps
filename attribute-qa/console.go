// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

// The browser console: the half of the model a headless suite cannot reach.
//
// A government-backed disclosure needs a real wallet, a real document and a
// human tap. What a QA tool CAN do is make that ceremony one click to start
// and completely legible when it lands: pick any attributes, run the real
// authorization, and read back exactly what arrived — which keys, at what
// assurance, as a raw value or as an enclave-signed disclosure, and what the
// achieved acr says about the whole set.

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type console struct {
	env       *Env
	admin     *IdPAdmin
	apiBase   string
	issuer    string
	accountID string

	mu   sync.Mutex
	last *consoleResult
}

// handleClient returns the relying party for one selection, registering it if
// this is the first time that exact set has been asked for.
func (c *console) handleClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Asked []string `json:"asked"`
		// Stable reuses one relying party across selections (whitelist
		// rewritten each run) — the attribute step-up scenario, where a
		// KNOWN client asks for more than the holder's standing grant.
		Stable bool `json:"stable"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.Asked) == 0 {
		http.Error(w, "pick at least one attribute", http.StatusBadRequest)
		return
	}
	id, err := c.admin.EnsurePublicClient(c.env.Redirect, body.Asked, body.Stable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Only a billable relying party gets disclosure vouchers, and without a
	// voucher a government-backed attribute never arrives.
	if err := c.admin.MakeBillable(id, c.accountID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"client_id": id})
}

type consoleResult struct {
	Asked        []string          `json:"asked"`
	ACR          string            `json:"acr"`
	Received     []receivedClaim   `json:"received"`
	Missing      []string          `json:"missing"`
	Raw          map[string]any    `json:"raw_claims"`
	Requirements map[string]AttributeRequirement `json:"requirements"`
}

type receivedClaim struct {
	Key       string `json:"key"`
	Assurance string `json:"assurance"`
	// Form distinguishes a value the holder typed from one an enclave signed.
	// Reading it off the shape is the point: a relying party that cannot tell
	// them apart has no assurance at all.
	Form  string `json:"form"`
	Value string `json:"value"`
	// Issuer is the verifier enclave that signed a government-backed
	// disclosure — the thing a relying party pins.
	Issuer string `json:"issuer,omitempty"`
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	common := bindCommon(fs)
	port := fs.Int("port", 8099, "console port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	common.resolve()

	redirect := fmt.Sprintf("http://localhost:%d/callback", *port)
	env, err := newEnv(common, redirect)
	if err != nil {
		return err
	}

	if common.idpAdminToken == "" {
		return fmt.Errorf("serve needs the IdP admin token to register a relying party per selection.\n" +
			"  Set --idp-admin-token or IDP_ADMIN_TOKEN.\n" +
			"  Prod: gcloud compute ssh idp-fr-par-1 --project privasys-production --zone europe-west9-a \\\n" +
			"          --command \"sudo docker exec idp cat /data/admin-token.txt\"")
	}

	accountID, err := env.Platform.AccountID()
	if err != nil {
		return fmt.Errorf("resolving the account that pays for disclosures: %w", err)
	}

	c := &console{
		env:       env,
		admin:     NewIdPAdmin(common.issuer, common.idpAdminToken),
		apiBase:   common.endpoint,
		issuer:    common.issuer,
		accountID: accountID,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handleIndex)
	mux.HandleFunc("/client", c.handleClient)
	mux.HandleFunc("/report", c.handleReport)
	mux.HandleFunc("/last.json", c.handleLast)

	fmt.Printf("attribute-qa console on http://localhost:%d\n", *port)
	fmt.Printf("  control plane : %s\n", common.endpoint)
	fmt.Printf("  issuer        : %s\n\n", common.issuer)
	fmt.Println("Tick attributes, press the button, scan the QR with your wallet.")
	fmt.Println("Each selection gets its own relying party, whitelisted for exactly")
	fmt.Println("those attributes — so the wallet offers what you ticked, nothing more.")
	fmt.Printf("\nGovernment-backed disclosures are CHARGED to account %s\n", accountID)
	fmt.Println("at the registry price (10,000 credits each). Free tiers cost nothing.")
	return http.ListenAndServe(fmt.Sprintf(":%d", *port), mux)
}

func (c *console) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	type row struct {
		Key, Label, Assurance string
		Priced                bool
		RequestOnly           bool
	}
	var rows []row
	for _, a := range c.env.Ref.Attributes {
		rows = append(rows, row{
			Key: a.Key, Label: a.Label, Assurance: a.Assurance,
			Priced: a.IsPriced(), RequestOnly: a.RequestOnly,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })

	c.mu.Lock()
	last := c.last
	c.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTmpl.Execute(w, map[string]any{
		"Rows":    rows,
		"APIBase": c.apiBase,
		"Issuer":  c.issuer,
		"Last":    last,
	})
}

// handleReport receives the ID token the SDK obtained in the browser and
// analyses it.
//
// The ceremony itself is run by the hosted SDK bundle — the same
// `privasys-auth-client.iife.js` an adopter site loads — because that is the
// only path that renders a QR the wallet can scan, handles the relay, and
// behaves the way a real integration behaves. An earlier version of this
// console redirected the browser straight at `/authorize`, which always
// answers JSON: what you got was a blob on screen and no way to proceed.
func (c *console) handleReport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Asked       []string `json:"asked"`
		AccessToken string   `json:"access_token"`
		Disclosures []struct {
			Claim     string         `json:"claim"`
			Value     any            `json:"value"`
			Assurance string         `json:"assurance"`
			Issuer    string         `json:"issuer"`
			Evidence  map[string]any `json:"evidence"`
			Token     string         `json:"token"`
		} `json:"disclosures"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := &consoleResult{Asked: body.Asked, Raw: map[string]any{}}
	if body.AccessToken != "" {
		if claims, err := decodeJWTClaims(body.AccessToken); err == nil {
			res.Raw = claims
			res.ACR, _ = claims["acr"].(string)
		}
	}

	got := map[string]bool{}

	// A self-asserted attribute arrives as a plain claim on the access token;
	// only the government tier produces a disclosure. Reading disclosures alone
	// reported every free attribute as missing.
	for _, key := range body.Asked {
		v, ok := res.Raw[key]
		if !ok {
			continue
		}
		got[key] = true
		s := fmt.Sprint(v)
		res.Received = append(res.Received, receivedClaim{
			Key:       key,
			Assurance: c.env.Ref.ByKey[key].Assurance,
			Form:      claimForm(s),
			Value:     truncate(s, 120),
		})
	}

	for _, d := range body.Disclosures {
		if got[d.Claim] {
			continue // already reported from the token claim
		}
		got[d.Claim] = true
		// The SD-JWT VC is the evidence, so classify on THAT rather than on
		// the convenience value the SDK already unwrapped for the caller: a
		// relying party that trusts the value without the token has verified
		// nothing.
		form := "raw value"
		if looksLikeVC(d.Token) {
			form = "enclave-signed disclosure"
		}
		res.Received = append(res.Received, receivedClaim{
			Key:       d.Claim,
			Assurance: c.env.Ref.ByKey[d.Claim].Assurance,
			Form:      form,
			Value:     truncate(fmt.Sprint(d.Value), 120),
			Issuer:    d.Issuer,
		})
	}
	for _, key := range body.Asked {
		if !got[key] {
			res.Missing = append(res.Missing, key)
		}
	}

	c.mu.Lock()
	c.last = res
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// looksLikeVC reports whether a disclosure carries a real SD-JWT VC — a JWS
// with the SD-JWT '~' terminator — rather than a bare value.
func looksLikeVC(tok string) bool {
	return strings.Count(tok, ".") == 2 && strings.HasSuffix(tok, "~") && strings.HasPrefix(tok, "ey")
}

func (c *console) handleLast(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if last == nil {
		enc.Encode(map[string]any{"result": nil})
		return
	}
	enc.Encode(last)
}

// claimForm classifies a claim by shape: an SD-JWT disclosure is a JWS with a
// trailing '~', anything else is a value the holder supplied.
func claimForm(v string) string {
	if strings.Count(v, ".") == 2 && strings.HasSuffix(v, "~") && strings.HasPrefix(v, "ey") {
		return "enclave-signed disclosure"
	}
	return "raw value"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<meta charset="utf-8"><title>Attribute QA</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}
 table{border-collapse:collapse;width:100%}
 td,th{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
 .gov{color:#b45309;font-weight:600}
 .tag{font-size:11px;border:1px solid #ccc;border-radius:99px;padding:0 .4rem;margin-left:.3rem}
 code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px}
 button{padding:.5rem 1rem;font:inherit}
 /* The SDK sizes its iframe to this element's bounding box, so the gate is
    only ever as usable as the box we give it. Sized for the QR ceremony
    rather than left to collapse to nothing. */
 #gate{display:none;width:100%;max-width:30rem;height:44rem;margin:1.5rem auto;
       border:1px solid rgba(128,128,128,.3);border-radius:12px;overflow:hidden}
 #gate.on{display:block}
 #msg{margin-left:.75rem;opacity:.8}
 @media(prefers-color-scheme:dark){body{background:#111;color:#eee}
  td,th{border-color:#333} code{background:#222} .tag{border-color:#444}}
</style>
<h1>Attribute QA</h1>
<p>Each selection gets its own relying party, whitelisted for exactly the
attributes you tick — so the wallet offers those and nothing else.
Government-backed keys need a wallet holding a real document.</p>

<form id="pick" onsubmit="return start(event)">
 <p><label>Scope <input id="scope" value="openid email profile identity" size="40"></label></p>
 <p><label><input type="checkbox" id="stable" checked>
    Reuse one relying party across runs (step-up QA: widening a selection
    should push an approval to the wallet instead of showing a QR)</label></p>
 <table>
  <tr><th></th><th>Key</th><th>Label</th><th>Assurance</th></tr>
  {{range .Rows}}
  <tr>
   <td><input type="checkbox" name="attr" value="{{.Key}}" id="a-{{.Key}}"></td>
   <td><label for="a-{{.Key}}"><code>{{.Key}}</code></label>
       {{if .RequestOnly}}<span class="tag">request-only</span>{{end}}
       {{if .Priced}}<span class="tag">priced</span>{{end}}</td>
   <td>{{.Label}}</td>
   <td {{if eq .Assurance "gov_verified"}}class="gov"{{end}}>{{.Assurance}}</td>
  </tr>
  {{end}}
 </table>
 <p><button type="submit" id="go">Request these attributes</button>
    <span id="msg"></span></p>
</form>
<div id="gate"></div>

<!-- The ceremony is run by the SAME hosted bundle an adopter site loads, so
     the QR, the relay and the consent screen are the real ones rather than a
     QA imitation. -->
<script src="{{.Issuer}}/auth/privasys-auth-client.iife.js"></script>
<script>
async function start(e) {
  e.preventDefault();
  const asked = [...document.querySelectorAll('input[name=attr]:checked')].map(i => i.value);
  const msg = document.getElementById('msg');
  if (!asked.length) { msg.textContent = 'Pick at least one attribute.'; return false; }
  msg.textContent = 'Starting — scan the QR with your wallet…';
  document.getElementById('go').disabled = true;
  // Show and reveal the gate BEFORE connect(): the SDK measures the
  // container to size its iframe, so a hidden or zero-height box yields a
  // cramped, scrolling QR.
  const gate = document.getElementById('gate');
  gate.classList.add('on');
  gate.scrollIntoView({behavior: 'smooth', block: 'center'});
  try {
    // A relying party whitelisted for exactly this selection. The whitelist is
    // both the ceiling AND, for a request-only key, a form of naming — so a
    // client allowed everything would make the wallet offer everything.
    const stable = document.getElementById('stable').checked;
    const cres = await fetch('/client', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ asked, stable })
    });
    if (!cres.ok) throw new Error(await cres.text());
    const clientId = (await cres.json()).client_id;

    const frame = new Privasys.AuthFrame({
      apiBase: {{.APIBase}},
      authOrigin: {{.Issuer}},
      appName: 'Attribute QA',
      rpId: 'privasys.id',
      clientId: clientId,
      scope: document.getElementById('scope').value.trim().split(/\s+/),
      attributes: asked,
      presentation: 'inline',
      container: document.getElementById('gate')
    });
    // connect() is the adopter path, and since the widening fix it is also
    // the QA path: a session that still covers the selection restores
    // silently, a WIDENED selection runs the step-up gate (wallet push,
    // falling back to the full ceremony), and a narrowed one reuses the
    // session. The old clearSession()+signIn() workaround dates from when
    // connect() restored a stale session regardless of what was asked.
    // NB the session store is keyed by rpId (shared privasys.id), so in
    // fresh-per-selection mode a narrowed selection reuses the PREVIOUS
    // client's session — use the stable relying party to QA step-up.
    const out = await frame.connect();
    const res = await fetch('/report', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        asked,
        // Self-asserted attributes ride the access token; government-backed
        // ones arrive as disclosures carrying the enclave-signed VC. A QA tool
        // has to look in both or it reports half the model missing.
        access_token: out.accessToken || '',
        disclosures: (out.result && out.result.disclosures) || []
      })
    });
    if (!res.ok) { msg.textContent = 'Report failed: ' + await res.text(); return false; }
    location.reload();
  } catch (err) {
    msg.textContent = 'Failed: ' + (err && err.message ? err.message : err);
    document.getElementById('go').disabled = false;
    gate.classList.remove('on');
  }
  return false;
}
</script>

{{with .Last}}
<h2>Last result — acr <code>{{.ACR}}</code></h2>
<table>
 <tr><th>Key</th><th>Assurance</th><th>Form</th><th>Value</th><th>Signed by</th></tr>
 {{range .Received}}
 <tr><td><code>{{.Key}}</code></td>
     <td {{if eq .Assurance "gov_verified"}}class="gov"{{end}}>{{.Assurance}}</td>
     <td>{{.Form}}</td><td><code>{{.Value}}</code></td>
     <td>{{if .Issuer}}<code>{{.Issuer}}</code>{{else}}—{{end}}</td></tr>
 {{end}}
</table>
{{if .Missing}}<p><strong>Asked for but not received:</strong>
 {{range .Missing}}<code>{{.}}</code> {{end}}</p>{{end}}
<p><a href="/last.json">last.json</a></p>
{{end}}
`))
