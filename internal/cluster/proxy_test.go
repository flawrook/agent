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
	"bufio"
	"context"
	"encoding/pem"
	"io"
	"log"
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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"flawrook.dev/agent/internal/client"
	"flawrook.dev/agent/internal/config"
)

// The chart passes the proxy as HTTPS_PROXY and NO_PROXY; they reach the registry client through config.Load and
// client.Transport, the same transport FlawRook's client uses. example.com is in httptest's certificate and is never
// resolved: the CONNECT proxy is the only way to the registry.
func TestTheChartsProxyEnvReachesTheRegistry(t *testing.T) {
	srv := httptest.NewTLSServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	repo := "example.com:" + port + "/lib/app"

	// Pushed straight to the server (not through the proxy) under the example.com name.
	direct := srv.Client().Transport.(*http.Transport).Clone()
	direct.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	img := alpineLike(t, "linux", "amd64", "", "proxied")
	ref, _ := name.ParseReference(repo + ":1")
	if err := remote.Write(ref, img, remote.WithTransport(direct)); err != nil {
		t.Fatal(err)
	}
	digest, _ := img.Digest()

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
		up, err := net.Dial("tcp", addr)
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
	defer p.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)

	env := map[string]string{"HTTPS_PROXY": p.URL, "FLAWROOK_CA_FILE": ca, "FLAWROOK_MODE": "cluster"}
	cfg, err := config.Load(config.Sources{Env: func(k string) string { return env[k] }, Path: filepath.Join(t.TempDir(), "none.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := client.Transport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registry{Transport: transport, UserAgent: "flawrook-agent/test", Env: func(string) string { return "" },
		Sleep: func(context.Context, time.Duration) error { return nil },
		extra: []remote.Option{remote.WithRetryBackoff(remote.Backoff{Steps: 1})}}
	res, st := reg.Resolve(context.Background(), Image{ImageKey: ImageKey{digest.String(), "linux/amd64"}, Repo: repo})
	if st != nil || res.ManifestDigest != digest.String() {
		t.Fatalf("through the proxy: %+v %+v", res, st)
	}
	mu.Lock()
	got := strings.Join(connects, ",")
	mu.Unlock()
	if !strings.HasPrefix(got, "example.com:"+port) {
		t.Fatalf("CONNECTs %q", got)
	}

	// NO_PROXY from the chart's env takes the registry off the proxy.
	env["NO_PROXY"] = "example.com"
	cfg, err = config.Load(config.Sources{Env: func(k string) string { return env[k] }, Path: filepath.Join(t.TempDir(), "none.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://" + repo + "/v2/")
	if via, err := client.ProxyFunc(cfg)(u); err != nil || via != nil {
		t.Fatalf("NO_PROXY: proxy %v %v", via, err)
	}
}
