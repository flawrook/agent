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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Registry reads images from their registries: the digest a runtime reported, the platform manifest its node runs,
// and the layers into an OCI layout for Syft. Its transport is the config's (proxy and CA), never the apiserver's.
type Registry struct {
	Transport http.RoundTripper
	UserAgent string
	Env       func(string) string // HOME and DOCKER_CONFIG, as go-containerregistry's default keychain reads them
	Sleep     func(ctx context.Context, d time.Duration) error

	extra       []remote.Option // tests: no retry backoff
	keychain    authn.Keychain
	configHash  string // the registry config file's content, to see the kubelet's swap of a mounted Secret
	configBad   string // why the file can't be used ("" when it can): pulls are then anonymous
	credentials map[string]bool
}

// Resolved is an image ready to download.
type Resolved struct {
	image            v1.Image
	ManifestDigest   string
	ResolvedPlatform string // the index entry picked, variant included
	SizeBytes        int64  // the manifest's compressed layers
}

// Round reads the registry config before a build round. It answers whether the file changed since the last round
// (private images are then tried again) and, when it doesn't parse, says so once per change: pulls go anonymous,
// so public images still build.
func (r *Registry) Round() (changed bool, warning string) {
	path := r.configPath()
	raw, err := os.ReadFile(path)
	sum := ""
	if err == nil {
		h := sha256.Sum256(raw)
		sum = hex.EncodeToString(h[:])
	}
	changed = r.keychain != nil && sum != r.configHash
	if r.keychain != nil && !changed {
		return false, ""
	}
	r.configHash, r.configBad, r.credentials = sum, "", map[string]bool{}
	r.keychain = authn.DefaultKeychain // it reloads the file on every resolve
	if err != nil {
		return changed, ""
	}
	var cfg struct {
		Auths       map[string]json.RawMessage `json:"auths"`
		CredsStore  string                     `json:"credsStore"`
		CredHelpers map[string]string          `json:"credHelpers"`
	}
	switch {
	case json.Unmarshal(raw, &cfg) != nil:
		r.configBad = "registry config file can't be read"
	case cfg.CredsStore != "" || len(cfg.CredHelpers) > 0:
		// A helper is a docker-credential-* binary the agent's image doesn't have: every pull would fail.
		r.configBad = "registry config file names a credential helper; only plain auths work"
	}
	if r.configBad != "" {
		r.keychain = anonymous{}
		return changed, "the registry config file " + path + ": " + r.configBad + ": pulling anonymously, private images won't build"
	}
	for host := range cfg.Auths {
		r.credentials[registryHost(host)] = true
	}
	return changed, ""
}

type anonymous struct{}

func (anonymous) Resolve(authn.Resource) (authn.Authenticator, error) { return authn.Anonymous, nil }

// configPath is the file the default keychain reads: $HOME/.docker/config.json if it exists, else
// $DOCKER_CONFIG/config.json.
func (r *Registry) configPath() string {
	if home := r.Env("HOME"); home != "" {
		if p := filepath.Join(home, ".docker", "config.json"); fileExists(p) {
			return p
		}
	}
	if d := r.Env("DOCKER_CONFIG"); d != "" {
		return filepath.Join(d, "config.json")
	}
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// registryHost normalises a config.json auths key to the registry's host; Docker Hub has several spellings.
func registryHost(key string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
	h = strings.SplitN(h, "/", 2)[0]
	switch h {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return name.DefaultRegistry
	}
	return h
}

// Resolve reads the reported digest from the registry: an index gives the node's platform's entry (containerd's
// preference, see PickPlatform), a manifest is that image itself. Two manifest GETs for an index, one for a
// manifest. A status comes back when it can't.
func (r *Registry) Resolve(ctx context.Context, img Image) (Resolved, *Status) {
	ref, err := name.NewDigest(img.Repo + "@" + img.Digest)
	if err != nil {
		return Resolved{}, &Status{Status: Error, Reason: "pull-failed", Detail: detail(err)}
	}
	host := ref.Context().RegistryStr()
	opts := r.options(ctx)
	var desc *remote.Descriptor
	for attempt := 1; ; attempt++ {
		desc, err = remote.Get(ref, opts...)
		if err == nil || !unreachable(err) || attempt == 3 {
			break
		}
		if err := r.Sleep(ctx, time.Duration(attempt)*2*time.Second); err != nil {
			return Resolved{}, r.classify(ctx, host, err)
		}
	}
	if err != nil {
		return Resolved{}, r.classify(ctx, host, err)
	}
	res := Resolved{ManifestDigest: desc.Digest.String(), ResolvedPlatform: img.Platform}
	switch {
	case desc.MediaType.IsIndex():
		idx, err := desc.ImageIndex()
		if err != nil {
			return Resolved{}, r.classify(ctx, host, err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return Resolved{}, r.classify(ctx, host, err)
		}
		child, ok := PickPlatform(im.Manifests, img.Platform)
		if !ok {
			return Resolved{}, &Status{Status: Error, Reason: "pull-failed", Detail: "the index has no image for " + img.Platform}
		}
		res.ManifestDigest, res.ResolvedPlatform = child.Digest.String(), platformString(child.Platform)
		if res.image, err = remote.Image(ref.Context().Digest(res.ManifestDigest), opts...); err != nil {
			return Resolved{}, r.classify(ctx, host, err)
		}
	case desc.MediaType.IsImage():
		if res.image, err = desc.Image(); err != nil {
			return Resolved{}, r.classify(ctx, host, err)
		}
	default:
		return Resolved{}, &Status{Status: Error, Reason: "pull-failed", Detail: "not an image: " + string(desc.MediaType)}
	}
	m, err := res.image.Manifest()
	if err != nil {
		return Resolved{}, r.classify(ctx, host, err)
	}
	for _, l := range m.Layers {
		res.SizeBytes += l.Size
	}
	return res, nil
}

// Download writes the image's config and layers into an OCI layout at dir, for Syft.
func (r *Registry) Download(ctx context.Context, res Resolved, dir string) *Status {
	p, err := layout.Write(dir, empty.Index)
	if err == nil {
		err = p.AppendImage(res.image)
	}
	if err != nil {
		return r.classify(ctx, "", err)
	}
	return nil
}

func (r *Registry) options(ctx context.Context) []remote.Option {
	if r.keychain == nil {
		r.Round()
	}
	return append([]remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(r.keychain), remote.WithTransport(r.Transport), remote.WithUserAgent(r.UserAgent)}, r.extra...)
}

// PickPlatform chooses an index entry the way containerd does on a node of that platform, not go-containerregistry's
// first match: nodes report no variant, so arm64 prefers v8 (or none), and arm prefers v7, then v6, then v5.
// Attestation entries (unknown/unknown) never match; an entry without a platform is linux/amd64.
func PickPlatform(manifests []v1.Descriptor, platform string) (v1.Descriptor, bool) {
	goos, arch, _ := strings.Cut(platform, "/")
	var preference []string
	switch arch {
	case "arm64":
		preference = []string{"v8", ""}
	case "arm":
		preference = []string{"v7", "v6", "v5"}
	}
	var matches []v1.Descriptor
	for _, d := range manifests {
		p := v1.Platform{OS: "linux", Architecture: "amd64"}
		if d.Platform != nil {
			p = *d.Platform
		}
		if p.OS == goos && p.Architecture == arch {
			matches = append(matches, d)
		}
	}
	for _, v := range preference {
		for _, d := range matches {
			if d.Platform != nil && d.Platform.Variant == v {
				return d, true
			}
		}
	}
	if len(matches) > 0 {
		return matches[0], true
	}
	return v1.Descriptor{}, false
}

func platformString(p *v1.Platform) string {
	if p == nil {
		return "linux/amd64"
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// classify turns a registry error into the contract's status; host is the registry's, "" for a layer download.
func (r *Registry) classify(ctx context.Context, host string, err error) *Status {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &Status{Status: Error, Reason: "timeout", Detail: "the build ran out of time"}
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		code := terr.StatusCode
		for _, d := range terr.Errors {
			switch d.Code {
			case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode:
				code = http.StatusNotFound
			case transport.UnauthorizedErrorCode, transport.DeniedErrorCode:
				if code != http.StatusForbidden {
					code = http.StatusUnauthorized
				}
			case transport.TooManyRequestsErrorCode:
				code = http.StatusTooManyRequests
			}
		}
		switch code {
		case http.StatusNotFound:
			return &Status{Status: NotPullable, Reason: "not-in-registry", Detail: "the registry has no image with this digest: deleted, or never pushed"}
		case http.StatusUnauthorized, http.StatusForbidden:
			switch {
			case r.configBad != "":
				return &Status{Status: PrivateNoCredential, Reason: "credential-refused", Detail: r.configBad}
			case r.credentials[host]:
				return &Status{Status: PrivateNoCredential, Reason: "credential-refused", Detail: fmt.Sprintf("%s refused the configured credential (%d)", host, code)}
			case host == name.DefaultRegistry:
				return &Status{Status: PrivateNoCredential, Reason: "no-credential", Detail: "Docker Hub answers 401 for private and missing repositories alike; no credential is configured for it"}
			default:
				return &Status{Status: PrivateNoCredential, Reason: "no-credential", Detail: fmt.Sprintf("%s asks for a credential (%d) and the registry config has none for it", host, code)}
			}
		case http.StatusTooManyRequests:
			return &Status{Status: Error, Reason: "rate-limited", Detail: "the registry's rate limit (429); a credential for it raises the limit"}
		}
		return &Status{Status: Error, Reason: "pull-failed", Detail: detail(err)}
	}
	if unreachable(err) {
		return &Status{Status: NotPullable, Reason: "registry-unreachable", Detail: detail(err)}
	}
	return &Status{Status: Error, Reason: "pull-failed", Detail: detail(err)}
}

// unreachable is a failure to resolve or reach the registry at all: air-gapped, egress blocked, or a mirror the
// agent can't see.
func unreachable(err error) bool {
	var dns *net.DNSError
	var op *net.OpError
	return errors.As(err, &dns) || errors.As(err, &op)
}

var userinfo = regexp.MustCompile(`://[^/@\s]+@`)

// detail is an error for a person to read: at most 200 characters, never a URL's userinfo.
func detail(err error) string {
	d := userinfo.ReplaceAllString(err.Error(), "://")
	if len(d) > 200 {
		d = d[:197] + "..."
	}
	return d
}
