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

package client

import (
	"bufio"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"flawrook.dev/agent/internal/config"
)

// A FlawRook stand-in over TLS (httptest's certificate is for 127.0.0.1 and example.com).
func server(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o644); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

func TestWithoutTheCABundleTheServerIsntTrusted(t *testing.T) {
	srv, _ := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	c, err := New(config.Config{URL: srv.URL, Token: "flra_x"}, "flawrook-agent/test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Heartbeat(context.Background(), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("got %v, want a certificate error", err)
	}
}

func TestTheCABundleIsTrustedAndTheHeadersAreTheContracts(t *testing.T) {
	var got []*http.Request
	var bodies []string
	srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, string(b))
		if r.URL.Path == ReportPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(202)
			_, _ = io.WriteString(w, `{"reportHash":"sha256:abc","url":"https://flawrook.example/repositories/r1"}`)
			return
		}
		w.WriteHeader(204)
	})
	c, err := New(config.Config{URL: srv.URL, Token: "flra_secret1234", CAFile: ca}, "flawrook-agent/0.1.0 (linux; arm64)") // gitleaks:allow: a made-up test token
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Report(context.Background(), []byte("gz"))
	if err != nil || res.Status != 202 || res.URL != "https://flawrook.example/repositories/r1" || res.ReportHash != "sha256:abc" {
		t.Fatalf("report: %+v %v", res, err)
	}
	if res, err = c.Heartbeat(context.Background(), []byte(`{"protocol":1}`)); err != nil || res.Status != 204 {
		t.Fatalf("heartbeat: %+v %v", res, err)
	}
	for i, path := range []string{ReportPath, HeartbeatPath} {
		r := got[i]
		if r.Method != "POST" || r.URL.Path != path {
			t.Errorf("%d: %s %s", i, r.Method, r.URL.Path)
		}
		for k, v := range map[string]string{"Authorization": "Bearer flra_secret1234", "FlawRook-Agent-Protocol": "1", "User-Agent": "flawrook-agent/0.1.0 (linux; arm64)", "Content-Type": "application/json"} {
			if r.Header.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", path, k, r.Header.Get(k), v)
			}
		}
	}
	if got[0].Header.Get("Content-Encoding") != "gzip" || got[1].Header.Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding: report %q, heartbeat %q", got[0].Header.Get("Content-Encoding"), got[1].Header.Get("Content-Encoding"))
	}
	if bodies[0] != "gz" || bodies[1] != `{"protocol":1}` {
		t.Errorf("bodies %q", bodies)
	}
}

func TestACABundleWithoutACertificateIsAnError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o644)
	if _, err := New(config.Config{URL: "https://flawrook.example", CAFile: bad}, "ua"); err == nil {
		t.Error("no error for a file without a certificate")
	}
	if _, err := New(config.Config{URL: "https://flawrook.example", CAFile: bad + ".absent"}, "ua"); err == nil {
		t.Error("no error for a missing file")
	}
}

// A CONNECT proxy that tunnels every request to the stand-in, whatever host it names.
func proxy(t *testing.T, target string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var connects []string
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", 405)
			return
		}
		mu.Lock()
		connects = append(connects, r.Host)
		mu.Unlock()
		up, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		conn, rw, _ := w.(http.Hijacker).Hijack()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = rw.Flush()
		go func() { _, _ = io.Copy(up, bufio.NewReader(conn)); up.Close() }()
		_, _ = io.Copy(conn, up)
		conn.Close()
	}))
	t.Cleanup(p.Close)
	return p, &connects
}

func TestTheProxyCarriesTheRequest(t *testing.T) {
	srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	p, connects := proxy(t, srv.Listener.Addr().String())
	// example.com is in httptest's certificate; it is never resolved, the proxy is the only way there.
	c, err := New(config.Config{URL: "https://example.com", Token: "flra_x", CAFile: ca, HTTPSProxy: p.URL}, "ua")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Heartbeat(context.Background(), []byte("{}"))
	if err != nil || res.Status != 204 {
		t.Fatalf("through the proxy: %+v %v", res, err)
	}
	if len(*connects) != 1 || (*connects)[0] != "example.com:443" {
		t.Fatalf("CONNECTs %v", *connects)
	}
}

func TestNoProxyAndNoSettingMeanDirect(t *testing.T) {
	target, _ := url.Parse("https://flawrook.internal.example/api/v1/agent/heartbeat")
	for name, c := range map[string]config.Config{
		"no proxy set":          {},
		"the host in no_proxy":  {HTTPSProxy: "http://proxy.example:3128", NoProxy: "internal.example"},
		"a wildcard no_proxy":   {HTTPSProxy: "http://proxy.example:3128", NoProxy: "*"},
		"a loopback url anyway": {HTTPSProxy: "http://proxy.example:3128"},
	} {
		u := target
		if name == "a loopback url anyway" {
			u, _ = url.Parse("http://127.0.0.1:3003/api/v1/agent/heartbeat")
		}
		if p, err := ProxyFunc(c)(u); err != nil || p != nil {
			t.Errorf("%s: proxy %v %v", name, p, err)
		}
	}
	p, err := ProxyFunc(config.Config{HTTPSProxy: "http://proxy.example:3128", NoProxy: "other.example"})(target)
	if err != nil || p == nil || p.Host != "proxy.example:3128" {
		t.Errorf("not in no_proxy: %v %v", p, err)
	}
}

func TestNoTokenSendsNothing(t *testing.T) {
	hits := 0
	srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) { hits++ })
	c, _ := New(config.Config{URL: srv.URL, CAFile: ca}, "ua")
	if _, err := c.Report(context.Background(), []byte("gz")); err == nil || hits != 0 {
		t.Fatalf("err %v, %d requests", err, hits)
	}
}

func TestErrorAnswersAndRetryAfter(t *testing.T) {
	answers := []func(w http.ResponseWriter){
		func(w http.ResponseWriter) { w.Header().Set("Retry-After", "7"); w.WriteHeader(429) },
		func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat))
			w.WriteHeader(429)
		},
		func(w http.ResponseWriter) {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"message":"report required"}`)
		},
		func(w http.ResponseWriter) { w.WriteHeader(502); _, _ = io.WriteString(w, "bad gateway\n") },
	}
	i := 0
	srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) { answers[i](w); i++ })
	c, _ := New(config.Config{URL: srv.URL, Token: "flra_x", CAFile: ca}, "ua")
	ctx := context.Background()
	r1, _ := c.Heartbeat(ctx, nil)
	r2, _ := c.Heartbeat(ctx, nil)
	r3, _ := c.Heartbeat(ctx, nil)
	r4, _ := c.Heartbeat(ctx, nil)
	if r1.Status != 429 || r1.RetryAfter != 7*time.Second {
		t.Errorf("seconds: %+v", r1)
	}
	if r2.Status != 429 || r2.RetryAfter < 80*time.Second || r2.RetryAfter > 90*time.Second {
		t.Errorf("a date: %+v", r2)
	}
	if r3.Status != 409 || r3.Message != "report required" {
		t.Errorf("409: %+v", r3)
	}
	if r4.Status != 502 || r4.Message != "bad gateway" {
		t.Errorf("502: %+v", r4)
	}
}

func TestTokenHint(t *testing.T) {
	if got := TokenHint("flra_abcdefgh1234"); got != "…1234" {
		t.Errorf("%q", got)
	}
	if got := TokenHint("abc"); got != "…" {
		t.Errorf("short: %q", got)
	}
}

// A redirect is never followed: Go would carry the token to the same host over plain http, and the body
// again on a 307. The answer comes back as is, with its Location.
func TestARedirectIsNeverFollowed(t *testing.T) {
	var plainHits int
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits++ }))
	t.Cleanup(plain.Close)
	for _, status := range []int{301, 302, 307, 308} {
		var tlsHits int
		srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) {
			tlsHits++
			http.Redirect(w, r, plain.URL+r.URL.Path, status) // the same host, 127.0.0.1, in clear
		})
		c, _ := New(config.Config{URL: srv.URL, Token: "flra_secretsecretWXYZ", CAFile: ca}, "ua")
		res, err := c.Report(context.Background(), []byte("gz"))
		if err != nil || res.Status != status || res.Location != plain.URL+ReportPath {
			t.Fatalf("%d: %+v %v", status, res, err)
		}
		if tlsHits != 1 || plainHits != 0 {
			t.Fatalf("%d: %d requests to the API, %d to the plain-http target", status, tlsHits, plainHits)
		}
	}
}

func TestClusterRoutes(t *testing.T) {
	type seen struct{ Path, Encoding, Protocol string }
	var mu sync.Mutex
	var got []seen
	big := `{"needed":[` + strings.Repeat(`{"digest":"sha256:`+strings.Repeat("a", 64)+`","platform":"linux/amd64"},`, 1000) + `{"digest":"x","platform":"y"}]}`
	srv, ca := server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.URL.Path, r.Header.Get("Content-Encoding"), r.Header.Get(ProtocolKey)})
		mu.Unlock()
		if r.URL.Path == ImagesNeededPath {
			w.WriteHeader(200)
			io.WriteString(w, big)
			return
		}
		w.WriteHeader(202)
	})
	c, err := New(config.Config{URL: srv.URL, Token: "flra_x", CAFile: ca}, "flawrook-agent/test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.ClusterReport(ctx, []byte("gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ClusterHeartbeat(ctx, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	res, err := c.ImagesNeeded(ctx, []byte("{}"))
	if err != nil || res.Status != 200 || string(res.Body) != big {
		t.Fatalf("images/needed: %d, %d of %d bytes, %v", res.Status, len(res.Body), len(big), err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	if _, err := c.ImageSBOM(ctx, digest, []byte("gz")); err != nil {
		t.Fatal(err)
	}
	want := []seen{
		{"/api/v1/agent/cluster/report", "gzip", "1"},
		{"/api/v1/agent/cluster/heartbeat", "", "1"},
		{"/api/v1/agent/cluster/images/needed", "", "1"},
		{"/api/v1/agent/cluster/images/" + digest + "/sbom", "gzip", "1"},
	}
	if len(got) != len(want) {
		t.Fatalf("requests %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
