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

package cluster

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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"flawrook.dev/agent/internal/client"
	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/kube"
)

// flawrook answers the cluster routes as the contract says: a heartbeat is 204 when its hash is the stored one,
// else 409; a report is stored (202); images/needed lists what the workspace holds no SBOM for; an upload is held.
// Queued statuses answer first, per route, with the route's message in say; a queued 0 drops the connection unanswered.
type flawrook struct {
	mu       sync.Mutex
	stored   string
	held     map[string]bool // digest/platform
	queue    map[string][]int
	say      map[string]string
	requests []string
	bodies   map[string]map[string]any // the last body per route
}

func newFlawrook(t *testing.T) (*flawrook, *client.Client) {
	t.Helper()
	f := &flawrook{held: map[string]bool{}, queue: map[string][]int{}, say: map[string]string{}, bodies: map[string]map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	c, err := client.New(config.Config{URL: srv.URL, Token: "flra_test", CAFile: ca}, "flawrook-agent/test")
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *flawrook) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	route := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/cluster/")
	if strings.HasSuffix(route, "/sbom") {
		route = "sbom"
	}
	f.requests = append(f.requests, route)
	f.bodies[route] = body
	if q := f.queue[route]; len(q) > 0 {
		f.queue[route] = q[1:]
		if q[0] == 0 {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		w.WriteHeader(q[0])
		if m := f.say[route]; m != "" {
			fmt.Fprintf(w, `{"message":%q}`, m)
		}
		return
	}
	switch route {
	case "heartbeat":
		if body["reportHash"] == f.stored && f.stored != "" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(409)
		fmt.Fprint(w, `{"message":"report required"}`)
	case "report":
		f.stored, _ = body["reportHash"].(string)
		w.WriteHeader(202)
		fmt.Fprintf(w, `{"reportHash":%q,"url":"https://flawrook.test/repositories/c1"}`, f.stored)
	case "images/needed":
		var needed []map[string]any
		for _, raw := range body["images"].([]any) {
			img := raw.(map[string]any)
			if !f.held[img["digest"].(string)+"/"+img["platform"].(string)] {
				needed = append(needed, img)
			}
		}
		raw, _ := json.Marshal(map[string]any{"needed": needed})
		w.WriteHeader(200)
		w.Write(raw)
	case "sbom":
		img := body["image"].(map[string]any)
		f.held[img["digest"].(string)+"/"+img["platform"].(string)] = true
		w.WriteHeader(202)
	}
}

func (f *flawrook) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.requests
	f.requests = nil
	return r
}

type fakeSource struct {
	pods     []kube.Pod
	nodes    []kube.Node
	complete bool
	next     [][]kube.Pod // each State takes the first as the pods, while there are any
}

func (s *fakeSource) Start(context.Context) {}
func (s *fakeSource) State() ([]kube.Pod, []kube.Node, bool) {
	if len(s.next) > 0 {
		s.pods, s.next = s.next[0], s.next[1:]
	}
	return s.pods, s.nodes, s.complete
}
func (s *fakeSource) Changed() <-chan struct{} { return nil }

// fakeImages builds every image unless told a status for its digest.
type fakeImages struct {
	mu            sync.Mutex
	resolveStatus map[string]*Status
	buildStatus   map[string]*Status
	size          int64
	configChanged bool
	built         []string
}

func (f *fakeImages) Round() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.configChanged
	f.configChanged = false
	return c, ""
}

func (f *fakeImages) Resolve(_ context.Context, img Image) (Resolved, *Status) {
	if st := f.resolveStatus[img.Digest]; st != nil {
		return Resolved{}, st
	}
	return Resolved{ManifestDigest: "sha256:" + strings.Repeat("f", 64), ResolvedPlatform: img.Platform + "/v8", SizeBytes: f.size}, nil
}

func (f *fakeImages) Build(_ context.Context, img Image, res Resolved) ([]byte, int, *Status) {
	f.mu.Lock()
	f.built = append(f.built, img.Digest)
	f.mu.Unlock()
	if st := f.buildStatus[img.Digest]; st != nil {
		return nil, 0, st
	}
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","version":"` + res.ManifestDigest + `"}},"components":[]}`), 1, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newRunner(t *testing.T, src *fakeSource, images *fakeImages) (*Runner, *flawrook, *clock) {
	t.Helper()
	f, c := newFlawrook(t)
	clk := &clock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	r := &Runner{Agent: Agent{Version: "0.3.0", OS: "linux", Arch: "arm64", Mode: Mode}, Config: config.Config{Token: "flra_test", Mode: "cluster"},
		Client: c, Source: src, Images: images, Backoff: nil, Sleep: func(context.Context, time.Duration) error { return nil },
		Now: clk.now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := r.Identify("3c8d3f0e-1b2a-4c5d-8e9f-0a1b2c3d4e5f", nil); err != nil {
		t.Fatal(err)
	}
	return r, f, clk
}

func webSource(imageIDs ...string) *fakeSource {
	src := &fakeSource{nodes: []kube.Node{node("w1", "arm64")}, complete: true}
	for i, id := range imageIDs {
		src.pods = append(src.pods, pod("shop", fmt.Sprintf("app%d-1", i), "w1", fmt.Sprintf("app%d", i), "h1", [3]string{"c", "app:1", id}))
	}
	return src
}

func equal(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("requests %v, want %v", got, want)
	}
}

func TestFirstRunReportsThenBuildsWhatsNeeded(t *testing.T) {
	r, f, _ := newRunner(t, webSource("docker.io/library/nginx@"+dA), &fakeImages{size: 1000})
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	// Nothing acknowledged yet: a heartbeat, 409, the report, then the images the workspace needs.
	equal(t, f.take(), "heartbeat", "report", "images/needed", "sbom")
	up := f.bodies["sbom"]
	img := up["image"].(map[string]any)
	if img["digest"] != dA || img["platform"] != "linux/arm64" || img["manifestDigest"] != "sha256:"+strings.Repeat("f", 64) ||
		img["resolvedPlatform"] != "linux/arm64/v8" || img["sizeBytes"] != 1000.0 || up["agent"].(map[string]any)["mode"] != "cluster" ||
		up["cluster"].(map[string]any)["id"] != "3f3e059a7c415f303269830f1a5a8951c4b4aa5d4675d3378d2e8fe18e10081a" {
		t.Fatalf("upload %v", up)
	}

	// The next interval: a heartbeat, the question, nothing to build.
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "images/needed")
	// A change that doesn't touch the controller-level snapshot (a pod restarted) sends nothing at all.
	if _, err := r.Cycle(context.Background(), OnChange); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take())
}

func TestReportsArePaced(t *testing.T) {
	src := webSource("docker.io/library/nginx@" + dA)
	r, f, clk := newRunner(t, src, &fakeImages{})
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	f.take()
	// A rollout to a new digest a minute later: the report waits for the 5 minutes.
	src.pods = webSource("docker.io/library/nginx@" + dB).pods
	clk.t = clk.t.Add(time.Minute)
	at, err := r.Cycle(context.Background(), OnChange)
	if err != nil || !at.Equal(clk.t.Add(4*time.Minute)) {
		t.Fatalf("retry at %v (%v), want %v", at, err, clk.t.Add(4*time.Minute))
	}
	equal(t, f.take())
	clk.t = at
	if _, err := r.Cycle(context.Background(), OnChange); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "report", "images/needed", "sbom")
}

func TestAFailedImageIsReportedHeldAndRetried(t *testing.T) {
	images := &fakeImages{resolveStatus: map[string]*Status{dB: {Status: PrivateNoCredential, Reason: "no-credential", Detail: "asks for a credential"}}}
	src := webSource("docker.io/library/nginx@"+dA, "ghcr.io/acme/private@"+dB)
	r, f, clk := newRunner(t, src, images)
	at, err := r.Cycle(context.Background(), OnInterval)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "images/needed", "sbom")
	// The status changed during the round: the report comes once the pacing allows.
	if !at.Equal(clk.t.Add(ReportPacing)) {
		t.Fatalf("retry at %v", at)
	}
	clk.t = at
	if _, err := r.Cycle(context.Background(), OnChange); err != nil {
		t.Fatal(err)
	}
	// Every run asks about the scannable images; the held one isn't due for a day.
	equal(t, f.take(), "report", "images/needed")
	if asked := fmt.Sprint(f.bodies["images/needed"]["images"]); strings.Contains(asked, dB) || !strings.Contains(asked, dA) {
		t.Fatalf("asked about %s", asked)
	}
	var private map[string]any
	for _, raw := range f.bodies["report"]["images"].([]any) {
		if img := raw.(map[string]any); img["digest"] == dB {
			private = img
		}
	}
	if private["status"] != PrivateNoCredential || private["reason"] != "no-credential" || private["detail"] != "asks for a credential" {
		t.Fatalf("the report's image %v", private)
	}
	// An hour later it still isn't asked about (daily), until the registry config changes.
	clk.t = clk.t.Add(time.Hour)
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "images/needed")
	if asked := fmt.Sprint(f.bodies["images/needed"]["images"]); strings.Contains(asked, dB) {
		t.Fatalf("asked about the held image: %s", asked)
	}
	images.configChanged = true
	delete(images.resolveStatus, dB)
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	// Built now: its status clears, and the report says so.
	equal(t, f.take(), "heartbeat", "images/needed", "sbom", "report")
}

func TestTooLargeIsNotBuilt(t *testing.T) {
	images := &fakeImages{size: 2 << 30}
	r, f, _ := newRunner(t, webSource("docker.io/library/big@"+dA), images)
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "images/needed")
	if len(images.built) != 0 {
		t.Fatal("a too-large image was built")
	}
	s := r.images[ImageKey{dA, "linux/arm64"}]
	if s == nil || s.status.Status != TooLarge || s.status.Reason != "image" || s.status.SizeBytes != 2<<30 || s.status.LimitBytes != 300<<20 || !s.retryAt.IsZero() {
		t.Fatalf("status %+v", s)
	}
}

func TestUploadAnswers(t *testing.T) {
	for _, tc := range []struct {
		code           int
		status, reason string
	}{{400, Error, "upload-rejected"}, {413, TooLarge, "sbom"}, {409, Error, "upload-rejected"}} {
		r, f, _ := newRunner(t, webSource("docker.io/library/nginx@"+dA), &fakeImages{})
		f.queue["sbom"] = []int{tc.code}
		if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
			t.Fatal(err)
		}
		s := r.images[ImageKey{dA, "linux/arm64"}]
		if s == nil || s.status.Status != tc.status || s.status.Reason != tc.reason {
			t.Errorf("%d: status %+v", tc.code, s)
		}
	}
}

func TestNeeded409SendsTheReportThenAsksAgain(t *testing.T) {
	r, f, _ := newRunner(t, webSource("docker.io/library/nginx@"+dA), &fakeImages{})
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	f.take()
	f.queue["images/needed"] = []int{409}
	f.held = map[string]bool{} // the server lost the cluster's images
	r.lastReport = time.Time{} // out of the pacing window
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "images/needed", "report", "images/needed", "sbom")
}

func TestIncompleteListsSendNothing(t *testing.T) {
	src := webSource("docker.io/library/nginx@" + dA)
	src.complete = false
	r, f, _ := newRunner(t, src, &fakeImages{})
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take())
}

func TestRetryAt(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		reason   string
		attempts int
		after    time.Duration
		never    bool
	}{
		{"pull-failed", 1, 0, false}, {"pull-failed", 2, time.Hour, false}, {"catalog-failed", 3, 6 * time.Hour, false}, {"timeout", 9, 24 * time.Hour, false},
		{"rate-limited", 1, time.Hour, false}, {"not-in-registry", 1, 24 * time.Hour, false}, {"registry-unreachable", 1, 24 * time.Hour, false},
		{"no-credential", 1, 24 * time.Hour, false}, {"credential-refused", 1, 24 * time.Hour, false},
		{"image", 1, 0, true}, {"sbom", 1, 0, true}, {"unsupported-platform", 1, 0, true},
	}
	for _, tc := range cases {
		at := RetryAt(Status{Reason: tc.reason}, tc.attempts, now)
		if tc.never != at.IsZero() || (!tc.never && !at.Equal(now.Add(tc.after))) {
			t.Errorf("%s after %d: %v", tc.reason, tc.attempts, at)
		}
	}
}

func TestCgroupMemoryAndLimit(t *testing.T) {
	root := t.TempDir()
	write := func(name, text string) { _ = os.WriteFile(filepath.Join(root, name), []byte(text), 0o644) }
	write("memory.current", "157286400\n")
	write("memory.peak", "209715200\n")
	write("memory.stat", "anon 104857600\nfile 52428800\nkernel 1\n")
	write("memory.max", "1073741824\n")
	got := fmt.Sprint(CgroupMemory(root, time.Hour)()())
	if got != "[memBuildMaxMiB 150 memCurrentMiB 150 memPeakMiB 200 memAnonMiB 100 memFileMiB 50]" {
		t.Errorf("memory %s", got)
	}
	if n := MemoryLimit(root); n != 805306368 {
		t.Errorf("limit %d", n)
	}
	write("memory.max", "max\n")
	if n := MemoryLimit(root); n != 0 {
		t.Errorf("unlimited gave %d", n)
	}
	if got := CgroupMemory(filepath.Join(root, "none"), time.Hour)()(); len(got) != 0 {
		t.Errorf("no cgroup gave %v", got)
	}
}

const dD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// logged gives the runner a log the test reads.
func logged(r *Runner) *bytes.Buffer {
	var b bytes.Buffer
	r.Log = slog.New(slog.NewTextHandler(&b, nil))
	return &b
}

// line is the first log line with this message.
func line(t *testing.T, logs *bytes.Buffer, msg string) string {
	t.Helper()
	for _, l := range strings.Split(logs.String(), "\n") {
		if l += " "; strings.Contains(l, " msg="+msg+" ") || strings.Contains(l, ` msg="`+msg+`" `) {
			return strings.TrimSuffix(l, " ")
		}
	}
	t.Fatalf("no %q line in:\n%s", msg, logs.String())
	return ""
}

// asked is the digests the last images/needed asked about, sorted.
func asked(f *flawrook) []string {
	var out []string
	for _, raw := range f.bodies["images/needed"]["images"].([]any) {
		out = append(out, raw.(map[string]any)["digest"].(string))
	}
	sort.Strings(out)
	return out
}

func images(t *testing.T, body map[string]any) string {
	t.Helper()
	var out []string
	for _, raw := range body["images"].([]any) {
		out = append(out, raw.(map[string]any)["digest"].(string))
	}
	return strings.Join(out, " ")
}

func TestAReportRetrySendsANewSnapshot(t *testing.T) {
	src := webSource("docker.io/library/nginx@"+dA, "docker.io/library/redis@"+dB)
	r, f, _ := newRunner(t, src, &fakeImages{})
	logs := logged(r)
	r.Backoff = []time.Duration{time.Second, time.Second, time.Second}
	sleeps := 0
	r.Sleep = func(context.Context, time.Duration) error {
		if sleeps++; sleeps == 1 {
			src.pods = src.pods[:1] // redis is removed during the first backoff
		}
		return nil
	}
	f.queue["report"] = []int{503, 503}
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "report", "report", "images/needed", "sbom")
	sent := f.bodies["report"] // the body that got the 202
	if got := images(t, sent); got != dA || len(sent["workloads"].([]any)) != 1 {
		t.Fatalf("the report that got through lists %s and %d workloads", got, len(sent["workloads"].([]any)))
	}
	if r.acked != sent["reportHash"] || f.stored != r.acked {
		t.Fatalf("acked %s, the body's hash %v", r.acked, sent["reportHash"])
	}
	if l := line(t, logs, "report sent"); !strings.Contains(l, " status=202 ") || !strings.HasSuffix(l, " workloads=1 images=1 reportHash="+r.acked) {
		t.Fatalf("report line %s", l)
	}
}

func TestARetriedSyncBuildsOnlyWhatBothListsHold(t *testing.T) {
	a, b, c := "docker.io/library/nginx@"+dA, "docker.io/library/redis@"+dB, "docker.io/library/httpd@"+dC
	src := webSource(a, b)
	// The run's start sees A and B, the retry A, B and C; C got through in the report, and B stopped just after.
	src.next = [][]kube.Pod{webSource(a, b).pods, webSource(a, b, c).pods, webSource(a, c).pods}
	r, f, _ := newRunner(t, src, &fakeImages{})
	r.Backoff = []time.Duration{time.Second}
	f.queue["report"] = []int{503}
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "report", "images/needed", "sbom", "sbom")
	if got := images(t, f.bodies["report"]); got != dA+" "+dB+" "+dC {
		t.Fatalf("the report lists %s", got)
	}
	if got := asked(f); strings.Join(got, " ") != dA+" "+dC {
		t.Fatalf("asked about %v: want the images the report holds that still run", got)
	}
}

func TestAnImageTheReportDoesntListWaitsForTheNextReport(t *testing.T) {
	a, d := "docker.io/library/nginx@"+dA, "docker.io/library/postgres@"+dD
	src := webSource(a)
	// D starts while the attempt that gets through is on its way: the build round sees it, the server's report doesn't.
	src.next = [][]kube.Pod{webSource(a).pods, webSource(a).pods, webSource(a, d).pods}
	r, f, clk := newRunner(t, src, &fakeImages{})
	r.Backoff = []time.Duration{time.Second}
	f.queue["report"] = []int{503}
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "report", "images/needed", "sbom")
	if got := asked(f); strings.Join(got, " ") != dA {
		t.Fatalf("asked about %v in the run that didn't report D", got)
	}
	// The change's run, once the pacing allows: the report lists D, then D is asked about and built.
	clk.t = clk.t.Add(ReportPacing)
	if _, err := r.Cycle(context.Background(), OnChange); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "report", "images/needed", "sbom")
	if got := asked(f); !strings.Contains(strings.Join(got, " "), dD) {
		t.Fatalf("asked about %v after the report", got)
	}
}

func TestAStaleHeartbeatSendsTheReport(t *testing.T) {
	a, b := "docker.io/library/nginx@"+dA, "docker.io/library/redis@"+dB
	// The first run, nothing acknowledged: the heartbeat is a probe, and once B has started it's stale.
	src := webSource(a)
	r, f, clk := newRunner(t, src, &fakeImages{})
	r.Backoff = []time.Duration{time.Second}
	r.Sleep = func(context.Context, time.Duration) error { src.pods = webSource(a, b).pods; return nil }
	f.queue["heartbeat"] = []int{503}
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	equal(t, f.take(), "heartbeat", "report", "images/needed", "sbom", "sbom")
	if got := images(t, f.bodies["report"]); got != dA+" "+dB {
		t.Fatalf("the report lists %s", got)
	}

	// Acknowledged a minute ago: the change's report waits for the pacing.
	clk.t = clk.t.Add(time.Minute)
	r.Sleep = func(context.Context, time.Duration) error { src.pods = webSource(a).pods; return nil }
	f.queue["heartbeat"] = []int{503}
	at, err := r.Cycle(context.Background(), OnInterval)
	if err != nil || !at.Equal(clk.t.Add(4*time.Minute)) {
		t.Fatalf("retry at %v (%v), want %v", at, err, clk.t.Add(4*time.Minute))
	}
	equal(t, f.take(), "heartbeat")
}

func TestARefusedUploadsBuiltLineSaysWhy(t *testing.T) {
	long := strings.Repeat("x", 300)
	for _, tc := range []struct {
		code    int
		message string
		want    string // the line's end
	}{
		{409, "report required", ` status=error/upload-rejected httpStatus=409 reason="report required"`},
		{413, "body over the limit", ` status=too-large/sbom httpStatus=413 reason="body over the limit"`},
		{400, long, ` status=error/upload-rejected httpStatus=400 reason=` + long[:200]},
		{0, "", ` status=error/upload-rejected httpStatus=0 reason=`},
		{202, "", ` status=uploaded`},
	} {
		r, f, _ := newRunner(t, webSource("docker.io/library/nginx@"+dA), &fakeImages{})
		logs := logged(r)
		if tc.code != 202 {
			f.queue["sbom"], f.say["sbom"] = []int{tc.code}, tc.message
		}
		if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
			t.Fatal(err)
		}
		l := line(t, logs, "built")
		switch {
		case tc.code == 0: // no answer: the error, which names the request
			if _, reason, _ := strings.Cut(l, tc.want); !strings.Contains(l, tc.want) || !strings.Contains(reason, "/sbom") || len([]rune(reason)) > 200+2 {
				t.Errorf("no answer: %s", l)
			}
		case !strings.HasSuffix(l, tc.want):
			t.Errorf("%d: %s", tc.code, l)
		}
		if tc.code == 202 && strings.Contains(l, "httpStatus") {
			t.Errorf("an upload that worked: %s", l)
		}
	}
}

func TestARetryOnIncompleteListsEndsTheRun(t *testing.T) {
	src := webSource("docker.io/library/nginx@" + dA)
	r, f, _ := newRunner(t, src, &fakeImages{})
	logs := logged(r)
	r.Backoff = []time.Duration{time.Second, time.Second}
	r.Sleep = func(context.Context, time.Duration) error { src.complete = false; return nil } // a watch restarts
	f.queue["report"] = []int{503}
	at, err := r.Cycle(context.Background(), OnInterval)
	if err != nil || !at.IsZero() || r.acked != "" {
		t.Fatalf("retry at %v, %v, acked %q", at, err, r.acked)
	}
	equal(t, f.take(), "heartbeat", "report")
	line(t, logs, "waiting for complete pod and node lists")
}
