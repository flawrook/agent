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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// alpineLike is a one-layer image Syft catalogs as Alpine with one apk package; tag tells images apart.
func alpineLike(t *testing.T, osName, arch, variant, tag string) v1.Image {
	t.Helper()
	img, err := crane.Image(map[string][]byte{
		"etc/os-release":       []byte("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"),
		"lib/apk/db/installed": []byte("P:musl\nV:1.2.5-r0\nA:x86_64\nT:the musl c library\nL:MIT\no:musl\n\n"),
		"tag":                  []byte(tag),
	})
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = osName, arch, variant
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

// testRegistry is an in-memory registry, where /v2/private/ asks for a credential and /v2/limited/ is rate limited.
func testRegistry(t *testing.T) string {
	t.Helper()
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v2/private/") && r.Method != http.MethodPut && !strings.Contains(r.URL.Path, "/blobs/uploads"):
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
		case strings.HasPrefix(r.URL.Path, "/v2/limited/") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"pull rate limit"}]}`)
		default:
			reg.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

var transportErr401 = transport.Error{StatusCode: http.StatusUnauthorized, Errors: []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}}}

func push(t *testing.T, ref string, v any) string {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	switch x := v.(type) {
	case v1.Image:
		if err := remote.Write(r, x); err != nil {
			t.Fatal(err)
		}
		d, _ := x.Digest()
		return d.String()
	case v1.ImageIndex:
		if err := remote.WriteIndex(r, x); err != nil {
			t.Fatal(err)
		}
		d, _ := x.Digest()
		return d.String()
	}
	t.Fatalf("push %T", v)
	return ""
}

func newRegistry(t *testing.T, env map[string]string) (*Registry, *int) {
	sleeps := 0
	r := &Registry{Transport: http.DefaultTransport, UserAgent: "flawrook-agent/test", Env: func(k string) string { return env[k] },
		Sleep: func(context.Context, time.Duration) error { sleeps++; return nil },
		extra: []remote.Option{remote.WithRetryBackoff(remote.Backoff{Steps: 1})}}
	return r, &sleeps
}

func TestResolveIndexPicksContainerdsPlatform(t *testing.T) {
	host := testRegistry(t)
	children := map[string]v1.Image{
		"linux/amd64":     alpineLike(t, "linux", "amd64", "", "amd64"),
		"linux/arm/v6":    alpineLike(t, "linux", "arm", "v6", "v6"),
		"linux/arm/v7":    alpineLike(t, "linux", "arm", "v7", "v7"),
		"linux/arm64/v8":  alpineLike(t, "linux", "arm64", "v8", "arm64"),
		"linux/arm64":     alpineLike(t, "linux", "arm64", "", "arm64-no-variant"),
		"windows/amd64":   alpineLike(t, "windows", "amd64", "", "windows"),
		"unknown/unknown": alpineLike(t, "unknown", "unknown", "", "attestation"),
	}
	idx := v1.ImageIndex(empty.Index)
	// Official images list arm/v6 before arm/v7. The attestation, a Windows image of the same architecture and an
	// arm64 entry without a variant come first here, to prove none of them is picked.
	for _, p := range []string{"unknown/unknown", "windows/amd64", "linux/amd64", "linux/arm/v6", "linux/arm/v7", "linux/arm64", "linux/arm64/v8"} {
		parts := strings.Split(p, "/")
		plat := &v1.Platform{OS: parts[0], Architecture: parts[1]}
		if len(parts) == 3 {
			plat.Variant = parts[2]
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: children[p], Descriptor: v1.Descriptor{Platform: plat}})
	}
	indexDigest := push(t, host+"/lib/app:1", idx)
	r, _ := newRegistry(t, nil)
	for node, want := range map[string]string{"linux/amd64": "linux/amd64", "linux/arm": "linux/arm/v7", "linux/arm64": "linux/arm64/v8"} {
		res, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{indexDigest, node}, Repo: host + "/lib/app"})
		if st != nil {
			t.Fatalf("%s: %+v", node, st)
		}
		d, _ := children[want].Digest()
		m, _ := children[want].Manifest()
		if res.ManifestDigest != d.String() || res.ResolvedPlatform != want || res.SizeBytes != m.Layers[0].Size {
			t.Errorf("%s: got %s %s %d, want %s %s %d", node, res.ManifestDigest, res.ResolvedPlatform, res.SizeBytes, d, want, m.Layers[0].Size)
		}
	}
	if _, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{indexDigest, "linux/s390x"}, Repo: host + "/lib/app"}); st == nil || st.Reason != "pull-failed" {
		t.Errorf("a platform the index lacks: %+v", st)
	}
}

func TestResolveAManifestIsItself(t *testing.T) {
	host := testRegistry(t)
	img := alpineLike(t, "linux", "amd64", "", "single")
	digest := push(t, host+"/lib/single:1", img)
	r, _ := newRegistry(t, nil)
	res, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{digest, "linux/amd64"}, Repo: host + "/lib/single"})
	if st != nil || res.ManifestDigest != digest || res.ResolvedPlatform != "linux/amd64" {
		t.Fatalf("%+v %+v", res, st)
	}
}

func TestResolveStatuses(t *testing.T) {
	host := testRegistry(t)
	img := alpineLike(t, "linux", "amd64", "", "any")
	digest := push(t, host+"/lib/any:1", img)
	missing := "sha256:" + strings.Repeat("e", 64)
	cfgDir := t.TempDir()
	// go-containerregistry's default keychain reads the process's own HOME and DOCKER_CONFIG, so they point at the
	// same file the agent checks: with a broken file, the keychain itself would fail every pull.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DOCKER_CONFIG", cfgDir)
	r, sleeps := newRegistry(t, map[string]string{"HOME": os.Getenv("HOME"), "DOCKER_CONFIG": cfgDir})

	check := func(repo, d, status, reason, detail string) {
		t.Helper()
		_, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{d, "linux/amd64"}, Repo: repo})
		if st == nil || st.Status != status || st.Reason != reason || !strings.Contains(st.Detail, detail) {
			t.Errorf("%s@%s: got %+v, want %s/%s with %q", repo, d[:12], st, status, reason, detail)
		}
	}
	check(host+"/lib/any", missing, NotPullable, "not-in-registry", "deleted, or never pushed")
	check(host+"/private/app", digest, PrivateNoCredential, "no-credential", host)
	check(host+"/limited/app", digest, Error, "rate-limited", "429")
	check("127.0.0.1:1/lib/app", digest, NotPullable, "registry-unreachable", "")
	if *sleeps != 2 {
		t.Errorf("an unreachable registry was tried %d+1 times, want 3", *sleeps)
	}

	// A configured credential that's refused, then a file that doesn't parse: pulls go anonymous and public
	// images still resolve.
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"auths":{"`+host+`":{"auth":"dTpw"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, _ := r.Round(); !changed {
		t.Error("a new config file wasn't seen as a change")
	}
	check(host+"/private/app", digest, PrivateNoCredential, "credential-refused", "refused the configured credential")
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"auths":`), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, warning := r.Round()
	if !changed || !strings.Contains(warning, "pulling anonymously") {
		t.Errorf("a broken file: changed %v, warning %q", changed, warning)
	}
	if changed, warning := r.Round(); changed || warning != "" {
		t.Errorf("an unchanged file: changed %v, warning %q", changed, warning)
	}
	check(host+"/private/app", digest, PrivateNoCredential, "credential-refused", "registry config file can't be read")
	if _, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{digest, "linux/amd64"}, Repo: host + "/lib/any"}); st != nil {
		t.Errorf("a public image with a broken config file: %+v", st)
	}
	// A credential helper the image doesn't have: treated the same, so public images still build.
	for _, helper := range []string{`{"auths":{},"credsStore":"desktop"}`, `{"credHelpers":{"` + host + `":"ecr-login"}}`} {
		if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(helper), 0o600); err != nil {
			t.Fatal(err)
		}
		if changed, warning := r.Round(); !changed || !strings.Contains(warning, "credential helper") {
			t.Errorf("%s: changed %v, warning %q", helper, changed, warning)
		}
		check(host+"/private/app", digest, PrivateNoCredential, "credential-refused", "names a credential helper")
		if _, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{digest, "linux/amd64"}, Repo: host + "/lib/any"}); st != nil {
			t.Errorf("%s: a public image: %+v", helper, st)
		}
	}
}

func TestDockerHubDetailAndHosts(t *testing.T) {
	r, _ := newRegistry(t, nil)
	r.Round()
	ref, _ := name.NewDigest("docker.io/library/nginx@sha256:" + strings.Repeat("a", 64))
	st := r.classify(context.Background(), ref.Context().RegistryStr(), &transportErr401)
	if st.Reason != "no-credential" || !strings.Contains(st.Detail, "Docker Hub answers 401 for private and missing repositories alike") {
		t.Errorf("Docker Hub: %+v", st)
	}
	for in, want := range map[string]string{"https://index.docker.io/v1/": "index.docker.io", "docker.io": "index.docker.io", "registry-1.docker.io": "index.docker.io",
		"ghcr.io": "ghcr.io", "https://registry.acme.io:5000/v2/": "registry.acme.io:5000"} {
		if got := registryHost(in); got != want {
			t.Errorf("registryHost(%q) = %q", in, got)
		}
	}
	if d := detail(fmt.Errorf("GET https://user:secret@registry.acme.io/v2/x: denied")); strings.Contains(d, "secret") {
		t.Errorf("detail kept userinfo: %s", d)
	}
}

func TestDownloadAndSBOM(t *testing.T) {
	host := testRegistry(t)
	img := alpineLike(t, "linux", "amd64", "", "sbom")
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}})
	indexDigest := push(t, host+"/lib/sbom:1", idx)
	r, _ := newRegistry(t, nil)
	res, st := r.Resolve(context.Background(), Image{ImageKey: ImageKey{indexDigest, "linux/amd64"}, Repo: host + "/lib/sbom"})
	if st != nil {
		t.Fatal(st)
	}
	dir := filepath.Join(t.TempDir(), "layout")
	if st := r.Download(context.Background(), res, dir); st != nil {
		t.Fatal(st)
	}
	ref := host + "/lib/sbom:1"
	raw, packages, err := SBOM(context.Background(), dir, ref, "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component struct{ Type, Name, Version string } `json:"component"`
		} `json:"metadata"`
		Components []struct{ Name, Version, Purl string } `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// The server checks the upload's path against metadata.component.version: the platform manifest digest.
	if c := doc.Metadata.Component; c.Type != "container" || c.Name != ref || c.Version != res.ManifestDigest {
		t.Fatalf("metadata.component %+v, manifest %s", c, res.ManifestDigest)
	}
	found := false
	for _, c := range doc.Components {
		found = found || (c.Name == "musl" && c.Version == "1.2.5-r0" && strings.HasPrefix(c.Purl, "pkg:apk/alpine/musl@1.2.5-r0"))
	}
	if !found || packages < 1 {
		t.Fatalf("musl not catalogued (%d packages): %+v", packages, doc.Components)
	}
}
