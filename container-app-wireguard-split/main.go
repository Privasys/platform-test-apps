// Command wireguard-split shows an enclave app reaching ONE private API through
// a WireGuard tunnel while every other connection goes out directly.
//
// The tunnel runs in userspace (wireguard-go with its gVisor netstack): the app
// container has no CAP_NET_ADMIN and no /dev/net/tun, so it cannot create an
// interface or change routes. Nothing in the container's network changes; the
// tunnel is a dialer that only the private API's HTTP client uses.
//
//	POST /configure  the WireGuard settings (owner only, enforced by the platform)
//	GET  /probe      one direct call, one call through the tunnel, and the same
//	                 private API dialled directly, which must fail
//	GET  /healthz
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// config is what POST /configure takes. Keys are WireGuard's base64 form.
type config struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	PresharedKey  string `json:"preshared_key,omitempty"`
	Endpoint      string `json:"endpoint"`   // host:port of the WireGuard server
	Address       string `json:"address"`    // this app's tunnel address, e.g. 10.66.66.8
	AllowedIP     string `json:"allowed_ip"` // the only prefix sent into the tunnel, e.g. 10.66.66.1/32
	DNS           string `json:"dns,omitempty"`
	PrivateURL    string `json:"private_url"` // the API behind the VPN
	DirectURL     string `json:"direct_url"`  // any public URL, reached without the VPN
}

type tunnel struct {
	cfg    config
	dev    *device.Device
	client *http.Client // dials through the tunnel only
}

var (
	mu  sync.Mutex
	cur *tunnel
)

func hexKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("a WireGuard key must be 32 bytes in base64")
	}
	return hex.EncodeToString(raw), nil
}

func up(c config) (*tunnel, error) {
	addr, err := netip.ParseAddr(c.Address)
	if err != nil {
		return nil, fmt.Errorf("address: %w", err)
	}
	allowed, err := netip.ParsePrefix(c.AllowedIP)
	if err != nil {
		return nil, fmt.Errorf("allowed_ip: %w", err)
	}
	var dns []netip.Addr
	if c.DNS != "" {
		d, err := netip.ParseAddr(c.DNS)
		if err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		dns = append(dns, d)
	}
	// The endpoint must be an IP:port for the IPC; resolve it with the normal
	// resolver, outside the tunnel.
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint: %w", err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("endpoint %s does not resolve: %v", host, err)
	}
	priv, err := hexKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	pub, err := hexKey(c.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("peer_public_key: %w", err)
	}

	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, dns, 1420)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=25\n",
		priv, pub, net.JoinHostPort(ips[0].String(), port), allowed)
	if c.PresharedKey != "" {
		psk, err := hexKey(c.PresharedKey)
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("preshared_key: %w", err)
		}
		ipc += "preshared_key=" + psk + "\n"
	}
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &tunnel{
		cfg: c,
		dev: dev,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{DialContext: tnet.DialContext},
		},
	}, nil
}

func handleConfigure(w http.ResponseWriter, r *http.Request) {
	var c config
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&c); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	for name, v := range map[string]string{"private_url": c.PrivateURL, "direct_url": c.DirectURL} {
		if _, err := url.ParseRequestURI(v); err != nil {
			http.Error(w, name+": "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	t, err := up(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mu.Lock()
	if cur != nil {
		cur.dev.Close()
	}
	cur = t
	mu.Unlock()
	log.Printf("tunnel up: %s via %s, only %s goes through it", c.Address, c.Endpoint, c.AllowedIP)
	json.NewEncoder(w).Encode(map[string]any{"configured": true, "address": c.Address, "allowed_ip": c.AllowedIP})
}

type result struct {
	Path   string `json:"path"`
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Ms     int64  `json:"ms"`
	Body   string `json:"body,omitempty"`
	Error  string `json:"error,omitempty"`
}

func fetch(c *http.Client, path, u string) result {
	start := time.Now()
	res := result{Path: path, URL: u}
	resp, err := c.Get(u)
	res.Ms = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	res.Status = resp.StatusCode
	res.Body = strings.TrimSpace(string(b))
	return res
}

func handleProbe(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	t := cur
	mu.Unlock()
	if t == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}
	direct := &http.Client{Timeout: 8 * time.Second}
	out := []result{
		fetch(direct, "direct", t.cfg.DirectURL),
		fetch(t.client, "tunnel", t.cfg.PrivateURL),
		fetch(direct, "direct (must fail)", t.cfg.PrivateURL),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /configure", handleConfigure)
	mux.HandleFunc("GET /probe", handleProbe)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
