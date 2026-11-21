// Copyright 2026 Binerals Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/hostinfo"
	"flawrook.dev/agent/internal/report"
)

// stub answers as the contract says: a report is stored (202), a heartbeat is 204 when its hash is the
// stored one, else 409. Queued statuses answer first, one per request.
type stub struct {
	mu       sync.Mutex
	srv      *httptest.Server
	ca       string
	stored   map[string]string // hostId: reportHash
	queue    []int
	requests []request
}

type request struct {
	Route, Token string
	Body         map[string]any
}

func newStub(t *testing.T) *stub {
	t.Helper()
	s := &stub{stored: map[string]string{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	s.ca = filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(s.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}), 0o644)
	return s
}

func (s *stub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var in io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		in = zr
	}
	var body map[string]any
	_ = json.NewDecoder(in).Decode(&body)
	route := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/")
	s.requests = append(s.requests, request{Route: route, Token: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), Body: body})
	if len(s.queue) > 0 {
		status := s.queue[0]
		s.queue = s.queue[1:]
		if status == 429 {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
		return
	}
	host, _ := body["host"].(map[string]any)
	id, _ := host["hostId"].(string)
	hash, _ := body["reportHash"].(string)
	switch route {
	case "report":
		s.stored[id] = hash
		w.WriteHeader(202)
		_, _ = io.WriteString(w, `{"reportHash":"`+hash+`","url":"https://flawrook.example/repositories/r1"}`)
	case "heartbeat":
		if s.stored[id] == hash {
			w.WriteHeader(204)
		} else {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"message":"report required"}`)
		}
	}
}

// routes are the requests' routes so far.
func (s *stub) routes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for _, r := range s.requests {
		out = append(out, r.Route)
	}
	return out
}

func (s *stub) last() request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[len(s.requests)-1]
}

const sbom1 = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:%d","metadata":{"timestamp":"%d"},"components":[{"name":"openssl","version":"3.0.15-1~deb12u1"}]}`

// testAgent is an agent over a fake host and inventory; sleeps are recorded, not slept.
type testAgent struct {
	*Agent
	sbom   string
	runs   int
	sleeps []time.Duration
}

func newAgent(t *testing.T, cfg func() (config.Config, error)) *testAgent {
	t.Helper()
	ta := &testAgent{sbom: sbom1}
	host := hostinfo.Reader{Root: t.TempDir(), StateDir: t.TempDir(), Uname: func() (string, error) { return "6.1.0-47-arm64", nil }, Hostname: func() (string, error) { return "web-1", nil }}
	_ = os.MkdirAll(filepath.Join(host.Root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(host.Root, "etc/machine-id"), []byte("0123456789abcdef0123456789abcdef\n"), 0o644)
	_ = os.WriteFile(filepath.Join(host.Root, "etc/os-release"), []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644)
	ta.Agent = &Agent{
		Agent:   report.Agent{Version: "0.1.0", OS: "linux", Arch: "arm64"},
		Load:    cfg,
		Host:    host.Read,
		Backoff: DefaultBackoff,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Scan: func(context.Context, config.Config) ([]byte, error) {
			ta.runs++
			// Every run's SBOM has its own serial number and timestamp, as Syft's do.
			return []byte(fmt.Sprintf(ta.sbom, ta.runs, ta.runs)), nil
		},
		Sleep: func(_ context.Context, d time.Duration) error { ta.sleeps = append(ta.sleeps, d); return nil },
	}
	return ta
}

func fixed(c config.Config) func() (config.Config, error) {
	return func() (config.Config, error) { return c, nil }
}

func (ta *testAgent) cycle(t *testing.T) error {
	t.Helper()
	if ta.client == nil {
		c, err := ta.Load()
		if err != nil {
			t.Fatal(err)
		}
		if err := ta.apply(c); err != nil {
			t.Fatal(err)
		}
	}
	return ta.Cycle(context.Background())
}

func TestHashSkipSendsAHeartbeatAndAChangeSendsTheReport(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca}))
	for i := 0; i < 3; i++ {
		if err := a.cycle(t); err != nil {
			t.Fatal(err)
		}
	}
	// The first run starts with a heartbeat too (nothing acknowledged yet); the empty stub answers 409.
	if got := s.routes(); !reflect.DeepEqual(got, []string{"heartbeat", "report", "heartbeat", "heartbeat"}) {
		t.Fatalf("unchanged inventory: %v", got)
	}
	hb := s.last().Body
	if hb["sbom"] != nil || hb["reportHash"] == nil || hb["protocol"] != float64(1) {
		t.Fatalf("heartbeat body %v", hb)
	}
	a.sbom = strings.Replace(sbom1, "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", 1)
	_ = a.cycle(t)
	_ = a.cycle(t)
	// A change since the acknowledged report goes straight to the report.
	if got := s.routes()[4:]; !reflect.DeepEqual(got, []string{"report", "heartbeat"}) {
		t.Fatalf("after a package upgrade: %v", got)
	}
}

func TestA409OnTheHeartbeatSendsTheReportAtOnce(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca}))
	_ = a.cycle(t)
	s.mu.Lock()
	s.stored = map[string]string{} // the server lost the entry
	s.mu.Unlock()
	if err := a.cycle(t); err != nil {
		t.Fatal(err)
	}
	_ = a.cycle(t)
	if got := s.routes(); !reflect.DeepEqual(got, []string{"heartbeat", "report", "heartbeat", "report", "heartbeat"}) {
		t.Fatalf("got %v", got)
	}
}

func TestAFailedReportIsSentAgainNextRun(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca}))
	s.queue = []int{409, 400} // the heartbeat asks for the report, which the server refuses
	if err := a.cycle(t); err == nil {
		t.Fatal("a 400 is no success")
	}
	_ = a.cycle(t)
	// Nothing was acknowledged: the next run's heartbeat gets 409 again, and the report follows.
	if got := s.routes(); !reflect.DeepEqual(got, []string{"heartbeat", "report", "heartbeat", "report"}) {
		t.Fatalf("got %v: an unacknowledged report must be sent again", got)
	}
}

func TestRetriesOn5xxWithBackoffAnd429WithRetryAfter(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca}))
	s.queue = []int{409, 500, 429, 503} // the heartbeat asks for the report, whose sending meets errors
	if err := a.cycle(t); err != nil {
		t.Fatal(err)
	}
	if got := s.routes(); !reflect.DeepEqual(got, []string{"heartbeat", "report", "report", "report", "report"}) {
		t.Fatalf("got %v", got)
	}
	if len(a.sleeps) != 3 || a.sleeps[1] != 7*time.Second {
		t.Fatalf("sleeps %v", a.sleeps)
	}
	for i, base := range map[int]time.Duration{0: 30 * time.Second, 2: 8 * time.Minute} {
		if d := a.sleeps[i]; d < base*8/10 || d > base*12/10 {
			t.Errorf("sleep %d: %v, want %v ±20%%", i, d, base)
		}
	}
	// Past the backoff the run gives up and the next one tries again.
	a.sleeps = nil
	a.sbom = strings.Replace(sbom1, "openssl", "libssl3", 1)
	s.queue = []int{500, 500, 500, 500}
	if err := a.cycle(t); err == nil || len(a.sleeps) != 3 {
		t.Fatalf("err %v, sleeps %v", err, a.sleeps)
	}
}

func TestA401IsNotRetriedAndTheTokenIsntLogged(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_secretsecretWXYZ", CAFile: s.ca}))
	s.queue = []int{401}
	err := a.cycle(t)
	if err == nil || len(s.routes()) != 1 || len(a.sleeps) != 0 {
		t.Fatalf("err %v, routes %v, sleeps %v", err, s.routes(), a.sleeps)
	}
	if !strings.Contains(err.Error(), "…WXYZ") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("the error shows the token: %v", err)
	}
}

func TestDryRunPrintsTheExactReportAndSendsNothing(t *testing.T) {
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca}))
	var out bytes.Buffer
	if err := a.DryRun(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if n := len(s.routes()); n != 0 {
		t.Fatalf("%d requests in a dry run", n)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if k := keys(got); !reflect.DeepEqual(k, []string{"agent", "host", "protocol", "reportHash", "sbom"}) {
		t.Fatalf("keys %v", k)
	}
	host := got["host"].(map[string]any)
	if k := keys(host); !reflect.DeepEqual(k, []string{"hostId", "hostIdSource", "hostname", "kernel", "osRelease"}) {
		t.Fatalf("host keys %v", k)
	}
	if !reflect.DeepEqual(got["agent"], map[string]any{"version": "0.1.0", "os": "linux", "arch": "arm64"}) || got["protocol"] != float64(1) {
		t.Fatalf("agent %v protocol %v", got["agent"], got["protocol"])
	}
	if host["kernel"] != "6.1.0-47-arm64" || host["hostIdSource"] != "machine-id" || host["hostname"] != "web-1" || len(host["hostId"].(string)) != 64 {
		t.Fatalf("host %v", host)
	}
	if !reflect.DeepEqual(host["osRelease"], map[string]any{"ID": "debian", "VERSION_ID": "12"}) {
		t.Fatalf("osRelease %v", host["osRelease"])
	}
	if got["sbom"].(map[string]any)["bomFormat"] != "CycloneDX" || !strings.HasPrefix(got["reportHash"].(string), "sha256:") {
		t.Fatalf("sbom or hash: %v", got["reportHash"])
	}
	// The exact payload: a report's own JSON, byte for byte, whose hash is its content's.
	var r report.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	body, _ := r.JSON()
	if !bytes.Equal(append(body, '\n'), out.Bytes()) {
		t.Fatalf("the dry run printed something else than a report body:\n%s\n%s", out.Bytes(), body)
	}
	if hash, _ := report.Hash(r.Agent, r.Host, r.SBOM); hash != r.ReportHash {
		t.Fatalf("hash %s, its content's %s", r.ReportHash, hash)
	}
}

func TestDryRunNeedsNoToken(t *testing.T) {
	a := newAgent(t, fixed(config.Config{URL: "https://flawrook.example"}))
	var out bytes.Buffer
	if err := a.DryRun(context.Background(), &out); err != nil || !bytes.Contains(out.Bytes(), []byte(`"reportHash"`)) {
		t.Fatalf("%v %s", err, out.String())
	}
}

// SIGHUP: the config file is read again; a change drops the acknowledged hash and runs at once with
// the new settings; the host keeps its id across a token rotation.
func TestSIGHUPReloadsTheConfig(t *testing.T) {
	s := newStub(t)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	write := func(text string) {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("url: " + s.srv.URL + "\ntoken: flra_first\nca_file: " + s.ca + "\n")
	load := func() (config.Config, error) {
		return config.Load(config.Sources{Env: func(string) string { return "" }, Path: path})
	}
	a := newAgent(t, load)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, time.Hour, 0) }()
	defer func() { cancel(); <-done }()

	waitFor := func(n int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if len(s.routes()) >= n {
				return
			}
		}
		t.Fatalf("waited for %d requests, got %v", n, s.routes())
	}
	hup := func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(2) // a heartbeat the empty stub answers 409, then the report
	first := s.last()
	if first.Route != "report" {
		t.Fatalf("the first run: %v", s.routes())
	}

	// Unchanged: no run (the next one is an hour away).
	hup()
	time.Sleep(300 * time.Millisecond)
	// Invalid: the previous config stays, no run.
	write("url: " + s.srv.URL + "\ntokn: flra_typo\n")
	hup()
	time.Sleep(300 * time.Millisecond)
	if got := s.routes(); len(got) != 2 {
		t.Fatalf("an unchanged or invalid config ran: %v", got)
	}

	// A new token: a run at once, with that token, for the same host. The server holds this inventory,
	// so the heartbeat it answers 204 is all: no full report again.
	write("url: " + s.srv.URL + "\ntoken: flra_second\nca_file: " + s.ca + "\n")
	hup()
	waitFor(3)
	second := s.last()
	if second.Route != "heartbeat" || second.Token != "flra_second" || first.Token != "flra_first" {
		t.Fatalf("after the reload: %s with %s (first %s)", second.Route, second.Token, first.Token)
	}
	time.Sleep(300 * time.Millisecond)
	if got := s.routes(); len(got) != 3 {
		t.Fatalf("a report followed the 204: %v", got)
	}
	id := func(r request) any { return r.Body["host"].(map[string]any)["hostId"] }
	if id(first) != id(second) || id(first) == nil {
		t.Fatalf("hostId changed with the token: %v, %v", id(first), id(second))
	}
}

func TestARedirectIsAnErrorNotFollowedNorRetried(t *testing.T) {
	var plainHits int
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits++ }))
	t.Cleanup(plain.Close)
	s := newStub(t)
	a := newAgent(t, fixed(config.Config{URL: s.srv.URL, Token: "flra_secretsecretWXYZ", CAFile: s.ca}))
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, request{Route: r.URL.Path})
		s.mu.Unlock()
		http.Redirect(w, r, plain.URL+"/api/v1/agent/report?token=x", http.StatusTemporaryRedirect)
	})
	err := a.cycle(t)
	if err == nil || !strings.Contains(err.Error(), "unexpected redirect to "+plain.URL+" (307)") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token=x") {
		t.Fatalf("the error shows a secret or the redirect's query: %v", err)
	}
	if n := len(s.routes()); n != 1 || plainHits != 0 || len(a.sleeps) != 0 {
		t.Fatalf("%d requests, %d to the redirect target, sleeps %v", n, plainHits, a.sleeps)
	}
}

// Heartbeat first after a start: a fleet-wide restart (a reboot, a crash, a reload) with unchanged
// inventories costs each host one heartbeat, not a full report. The server answers 204 when it holds
// this hash; a 409 brings the report, as when the inventory changed while the agent was down.
func TestARestartWithAnUnchangedInventoryCostsOnlyAHeartbeat(t *testing.T) {
	s := newStub(t)
	cfg := fixed(config.Config{URL: s.srv.URL, Token: "flra_a", CAFile: s.ca})
	if err := newAgent(t, cfg).cycle(t); err != nil {
		t.Fatal(err)
	}
	before := len(s.routes())
	if s.routes()[before-1] != "report" {
		t.Fatalf("the first run didn't end in a report: %v", s.routes())
	}
	restarted := newAgent(t, cfg) // a new process: nothing acknowledged in memory
	if err := restarted.cycle(t); err != nil {
		t.Fatal(err)
	}
	if got := s.routes()[before:]; !reflect.DeepEqual(got, []string{"heartbeat"}) {
		t.Fatalf("after a restart with the same inventory: %v, want one heartbeat", got)
	}
	// The 204 counts as acknowledged: a change afterwards goes straight to the report.
	restarted.sbom = strings.Replace(sbom1, "openssl", "libssl3", 1)
	_ = restarted.cycle(t)
	if got := s.routes()[before+1:]; !reflect.DeepEqual(got, []string{"report"}) {
		t.Fatalf("a change after the 204: %v, want the report alone", got)
	}
	changed := newAgent(t, cfg)
	changed.sbom = strings.Replace(sbom1, "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", 1)
	_ = changed.cycle(t)
	if got := s.routes()[before+2:]; !reflect.DeepEqual(got, []string{"heartbeat", "report"}) {
		t.Fatalf("after a restart with a changed inventory: %v, want a heartbeat answered 409, then the report", got)
	}
}
