// fixproof-holder: a dev-only fixture that proves the runtime's security
// fixes from INSIDE a container. Every probe route is declared
// x-privasys.auth "owner" in privasys.json, so the runtime (not this app)
// gates it. It carries no credential of its own; it is deleted after the
// proofs.
//
//	POST /holder/open   {subject}  ask the runtime to open the holder folder
//	POST /holder/probe  {}         try every write/escape the folder must refuse
//	POST /holder/keepfd {}         open a directory fd on the folder and keep it
//	POST /holder/fdwrite {}        create a file through the kept fd
//	/.well-known/attestation-extensions  302 to /trap (the runtime must not follow)
//	GET  /trap-count                    how many times /trap was reached
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

var (
	trapHits atomic.Int64
	keptMu   sync.Mutex
	keptFD   = -1
	folder   string // the container path the runtime returned
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/.well-known/attestation-extensions", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("extensions request: answering 302 to /trap")
		http.Redirect(w, r, "/trap", http.StatusFound)
	})
	mux.HandleFunc("/trap", func(w http.ResponseWriter, r *http.Request) {
		trapHits.Add(1)
		log.Printf("TRAP reached")
		_, _ = w.Write([]byte(`[{"oid":"1.3.6.1.4.1.65230.5.4.9","value":"dHJhcA=="}]`))
	})
	mux.HandleFunc("/trap-count", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"trap_hits": trapHits.Load()})
	})
	mux.HandleFunc("/holder/open", holderOpen)
	mux.HandleFunc("/holder/probe", holderProbe)
	mux.HandleFunc("/holder/keepfd", holderKeepFD)
	mux.HandleFunc("/holder/fdwrite", holderFDWrite)
	log.Printf("fixproof-holder listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, logged(mux)))
}

func logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(os.Stdout, "request %s %s\n", r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// holderOpen asks the runtime to open the "holders" resource for subject.
func holderOpen(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Subject string `json:"subject"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
	body, _ := json.Marshal(map[string]any{"subject": in.Subject, "uid": 0})
	req, _ := http.NewRequest(http.MethodPost,
		strings.TrimRight(os.Getenv("PRIVASYS_MANAGER_URL"), "/")+"/api/v1/resources/holders/open", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("PRIVASYS_CONTAINER_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if p, ok := out["path"].(string); ok && p != "" {
		folder = p
	}
	writeJSON(w, map[string]any{"status": resp.StatusCode, "runtime": out, "raw": string(raw)})
}

func errString(err error) string {
	if err == nil {
		return "OK"
	}
	return err.Error()
}

// holderProbe tries everything a read-only folder must refuse, and looks for
// any route to the runtime's private writable view.
func holderProbe(w http.ResponseWriter, r *http.Request) {
	res := map[string]any{"folder": folder}
	if folder == "" {
		res["error"] = "open the folder first"
		writeJSON(w, res)
		return
	}
	entries, err := os.ReadDir(folder)
	res["read_dir"] = errString(err)
	res["entries"] = len(entries)
	res["write_file"] = errString(os.WriteFile(filepath.Join(folder, "probe.txt"), []byte("x"), 0o600))
	res["mkdir"] = errString(os.Mkdir(filepath.Join(folder, "probe-dir"), 0o700))
	res["chmod_folder"] = errString(os.Chmod(folder, 0o777))
	// From the parent: the lookup crosses into the read-only bind.
	parent := filepath.Dir(folder)
	if pfd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY, 0); err == nil {
		fd, err := syscall.Openat(pfd, filepath.Base(folder)+"/via-parent.txt", syscall.O_CREAT|syscall.O_WRONLY, 0o600)
		if err == nil {
			syscall.Close(fd)
		}
		res["openat_via_parent"] = errString(err)
		syscall.Close(pfd)
	}
	// The container's root must not be able to undo the bind.
	res["remount_rw"] = errString(syscall.Mount("", folder, "", syscall.MS_BIND|syscall.MS_REMOUNT, ""))
	res["umount"] = errString(syscall.Unmount(folder, syscall.MNT_DETACH))
	res["new_mount"] = errString(syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, ""))
	// The runtime's private writable view must be unreachable from here.
	_, err = os.Stat("/run/manager/holders-rw")
	res["stat_holders_rw"] = errString(err)
	found := ""
	_ = filepath.WalkDir("/data", func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.Contains(p, "holders-rw") {
			found = p
		}
		return nil
	})
	res["holders_rw_under_data"] = found
	// How the kernel sees the folder's mount (read-only, slave of the host).
	if mi, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(mi), "\n") {
			if strings.Contains(line, " "+folder+" ") {
				res["mountinfo"] = line
			}
		}
	}
	writeJSON(w, res)
}

// holderKeepFD opens a directory fd on the folder and keeps it across a
// close and reopen of the folder.
func holderKeepFD(w http.ResponseWriter, r *http.Request) {
	keptMu.Lock()
	defer keptMu.Unlock()
	fd, err := syscall.Open(folder, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err == nil {
		keptFD = fd
	}
	writeJSON(w, map[string]any{"keepfd": errString(err), "fd": keptFD})
}

// holderFDWrite creates a file through the kept directory fd.
func holderFDWrite(w http.ResponseWriter, r *http.Request) {
	keptMu.Lock()
	defer keptMu.Unlock()
	if keptFD < 0 {
		writeJSON(w, map[string]any{"error": "no kept fd"})
		return
	}
	fd, err := syscall.Openat(keptFD, "via-kept-fd.txt", syscall.O_CREAT|syscall.O_WRONLY, 0o600)
	if err == nil {
		syscall.Close(fd)
	}
	writeJSON(w, map[string]any{"openat_kept_fd": errString(err)})
}
