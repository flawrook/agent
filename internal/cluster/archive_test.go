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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// twoLayers is a tiny Alpine-like image in two layers, the OS and then the package database, with musl at musl.
func twoLayers(t *testing.T, arch, variant, musl string) v1.Image {
	t.Helper()
	osLayer, err := crane.Layer(map[string][]byte{"etc/os-release": []byte("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n")})
	if err != nil {
		t.Fatal(err)
	}
	apk, err := crane.Layer(map[string][]byte{"lib/apk/db/installed": []byte("P:musl\nV:" + musl + "\nA:x86_64\nL:MIT\no:musl\n\n")})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, osLayer, apk)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = "linux", arch, variant
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

func digestOf(t *testing.T, get func() (v1.Hash, error)) string {
	t.Helper()
	h, err := get()
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

// tarFiles writes a tar of these files, in this order.
func tarFiles(t *testing.T, out string, files [][2]string) {
	t.Helper()
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := tar.NewWriter(f)
	for _, e := range files {
		if err := w.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, e[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// tarDir writes a tar of a directory's files, as `tar -C dir -cf out .` would.
func tarDir(t *testing.T, dir, out string) {
	t.Helper()
	var files [][2]string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		files = append(files, [2]string{"./" + filepath.ToSlash(rel), string(b)})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	tarFiles(t, out, files)
}

// dockerSave writes img as a classic `docker save`: the config as <hex>.json, each layer an uncompressed layer.tar,
// and manifest.json. It answers the archive's path and its layers' size.
func dockerSave(t *testing.T, img v1.Image, tags ...string) (string, int64) {
	t.Helper()
	config, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfgName := strings.TrimPrefix(digestOf(t, img.ConfigName), "sha256:") + ".json"
	files := [][2]string{{cfgName, string(config)}}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var size int64
	for i, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("layer%d/layer.tar", i)
		files, names, size = append(files, [2]string{name, string(b)}), append(names, name), size+int64(len(b))
	}
	manifest, _ := json.Marshal([]map[string]any{{"Config": cfgName, "RepoTags": tags, "Layers": names}})
	out := filepath.Join(t.TempDir(), "docker.tar")
	tarFiles(t, out, append(files, [2]string{"manifest.json", string(manifest)}))
	return out, size
}

type entry struct {
	img         v1.Image
	platform    *v1.Platform
	annotations map[string]string
}

// ociLayout writes an OCI layout of these images, each an entry of index.json.
func ociLayout(t *testing.T, entries ...entry) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "layout")
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		var opts []layout.Option
		if e.platform != nil {
			opts = append(opts, layout.WithPlatform(*e.platform))
		}
		if e.annotations != nil {
			opts = append(opts, layout.WithAnnotations(e.annotations))
		}
		if err := p.AppendImage(e.img, opts...); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func ociArchive(t *testing.T, entries ...entry) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "oci.tar")
	tarDir(t, ociLayout(t, entries...), out)
	return out
}

// modernDockerSave writes what `docker save` writes with the containerd image store: Docker's manifest.json beside
// an OCI index.json whose image index names two platforms, with only the amd64 image's blobs in the archive.
func modernDockerSave(t *testing.T, amd, arm v1.Image) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "save")
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}})
	if err := p.AppendIndex(idx, layout.WithAnnotations(map[string]string{"io.containerd.image.name": "registry.acme.example/shop:1.0"})); err != nil {
		t.Fatal(err)
	}
	blob := func(d string) string { return filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(d, "sha256:")) }
	armLayers, _ := arm.Layers()
	for _, d := range []string{digestOf(t, arm.Digest), digestOf(t, arm.ConfigName), digestOf(t, armLayers[1].Digest)} {
		if err := os.Remove(blob(d)); err != nil {
			t.Fatal(err)
		}
	}
	amdLayers, _ := amd.Layers()
	var names []string
	for _, l := range amdLayers {
		names = append(names, "blobs/sha256/"+strings.TrimPrefix(digestOf(t, l.Digest), "sha256:"))
	}
	manifest, _ := json.Marshal([]map[string]any{{"Config": "blobs/sha256/" + strings.TrimPrefix(digestOf(t, amd.ConfigName), "sha256:"),
		"RepoTags": []string{"registry.acme.example/shop:1.0"}, "Layers": names}})
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "saved.tar")
	tarDir(t, dir, out)
	return out
}

func compressedSize(t *testing.T, img v1.Image) int64 {
	t.Helper()
	layers, _ := img.Layers()
	var n int64
	for _, l := range layers {
		s, err := l.Size()
		if err != nil {
			t.Fatal(err)
		}
		n += s
	}
	return n
}

var (
	amd64   = &v1.Platform{OS: "linux", Architecture: "amd64"}
	arm64v8 = &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	// The annotations BuildKit's OCI exporter writes on index.json's entry (buildx -t … -o type=oci, 2026-11-23): the
	// full name, the tag alone, the build time.
	named = map[string]string{"io.containerd.image.name": "registry.acme.example/shop:1.0", "org.opencontainers.image.ref.name": "1.0",
		"org.opencontainers.image.created": "2026-11-23T17:49:55Z"}
)

func TestReadArchiveKinds(t *testing.T) {
	img := twoLayers(t, "amd64", "", "1.2.5-r0")
	arm := twoLayers(t, "arm64", "v8", "1.2.5-r9")
	cfg, man := digestOf(t, img.ConfigName), digestOf(t, img.Digest)
	docker, tarSize := dockerSave(t, img, "registry.acme.example/shop:1.0")
	for _, tc := range []struct {
		kind, path string
		want       Archive
	}{
		{"classic docker save, tar layers", docker, Archive{Tag: "docker-archive", Name: "registry.acme.example/shop:1.0", KeyKind: "config",
			ConfigDigest: cfg, Platform: "linux/amd64", SizeBytes: tarSize, Compressed: false}},
		{"OCI archive, gzip layers", ociArchive(t, entry{img, amd64, named}), Archive{Tag: "oci-archive", Name: "registry.acme.example/shop:1.0",
			KeyKind: "manifest", ManifestDigest: man, ConfigDigest: cfg, Platform: "linux/amd64", SizeBytes: compressedSize(t, img), Compressed: true}},
		{"OCI layout directory", ociLayout(t, entry{img, amd64, nil}), Archive{Tag: "oci-dir", KeyKind: "manifest", ManifestDigest: man,
			ConfigDigest: cfg, Platform: "linux/amd64", SizeBytes: compressedSize(t, img), Compressed: true}},
		{"modern docker save: manifest.json and index.json", modernDockerSave(t, img, arm), Archive{Tag: "docker-archive",
			Name: "registry.acme.example/shop:1.0", KeyKind: "config", ConfigDigest: cfg, Platform: "linux/amd64", SizeBytes: compressedSize(t, img), Compressed: true}},
	} {
		got, err := ReadArchive(tc.path, "linux/amd64")
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v (%v)\n want %+v", tc.kind, got, err, tc.want)
		}
	}
	if k := (Archive{KeyKind: "config", ConfigDigest: cfg, ManifestDigest: man}).Key(); k != cfg {
		t.Errorf("a config key: %s", k)
	}
	if k := (Archive{KeyKind: "manifest", ConfigDigest: cfg, ManifestDigest: man}).Key(); k != man {
		t.Errorf("a manifest key: %s", k)
	}
}

func TestReadArchivePlatform(t *testing.T) {
	amd, arm := twoLayers(t, "amd64", "", "1.2.5-r0"), twoLayers(t, "arm64", "v8", "1.2.5-r9")
	attestation := entry{twoLayers(t, "unknown", "", "0"), &v1.Platform{OS: "unknown", Architecture: "unknown"},
		map[string]string{"vnd.docker.reference.type": "attestation-manifest"}}
	both := ociArchive(t, entry{amd, amd64, named}, entry{arm, arm64v8, named}, attestation)
	for platform, want := range map[string]string{"linux/amd64": digestOf(t, amd.Digest), "linux/arm64": digestOf(t, arm.Digest), "linux/arm64/v8": digestOf(t, arm.Digest)} {
		if a, err := ReadArchive(both, platform); err != nil || a.ManifestDigest != want || !a.Several {
			t.Errorf("%s: %+v (%v)", platform, a, err)
		}
	}
	if _, err := ReadArchive(both, "linux/s390x"); err == nil || err.Error() != "the archive holds no image for linux/s390x, only for linux/amd64, linux/arm64/v8" {
		t.Errorf("s390x: %v", err)
	}
	// One image, an attestation beside it or not, is the image whatever the platform asked for.
	for _, p := range []string{ociArchive(t, entry{arm, arm64v8, nil}), ociArchive(t, entry{arm, arm64v8, nil}, attestation)} {
		if a, err := ReadArchive(p, "linux/amd64"); err != nil || a.ManifestDigest != digestOf(t, arm.Digest) || a.Several || a.Platform != "linux/arm64/v8" {
			t.Errorf("a single arm64 image: %+v (%v)", a, err)
		}
	}
}

func TestReadArchiveRefusals(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.tar")
	os.WriteFile(junk, []byte(strings.Repeat("not a tar ", 100)), 0o644)
	other := filepath.Join(dir, "other.tar")
	tarFiles(t, other, [][2]string{{"README", "hello"}})
	for _, p := range []string{junk, other, t.TempDir()} {
		if _, err := ReadArchive(p, "linux/amd64"); !errors.Is(err, ErrNotAnArchive) {
			t.Errorf("%s: %v", p, err)
		}
	}
	two := filepath.Join(dir, "two.tar")
	tarFiles(t, two, [][2]string{{"manifest.json", `[{"Config":"a.json","Layers":[]},{"Config":"b.json","Layers":[]}]`}})
	if _, err := ReadArchive(two, "linux/amd64"); err == nil || err.Error() != "the archive holds 2 images; save one" {
		t.Errorf("two images: %v", err)
	}
	if _, err := ReadArchive(filepath.Join(dir, "none.tar"), "linux/amd64"); err == nil {
		t.Error("a missing file read")
	}
}

type sbomDoc struct {
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component  struct{ Type, Name, Version string } `json:"component"`
		Properties []struct{ Name, Value string }       `json:"properties"`
		Tools      struct {
			Components []struct{ Name, Version string } `json:"components"`
		} `json:"tools"`
	} `json:"metadata"`
	Components []struct{ Type, Name, Version string } `json:"components"`
}

func parse(t *testing.T, raw []byte) sbomDoc {
	t.Helper()
	var d sbomDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func (d sbomDoc) props() map[string]string {
	m := map[string]string{}
	for _, p := range d.Metadata.Properties {
		if strings.HasPrefix(p.Name, "flawrook:") {
			m[p.Name] = p.Value
		}
	}
	return m
}

func (d sbomDoc) packages() string {
	var out []string
	for _, c := range d.Components {
		if c.Type != "operating-system" { // Syft's component for the distro
			out = append(out, c.Name+"@"+c.Version)
		}
	}
	return strings.Join(out, " ")
}

func TestArchiveSBOM(t *testing.T) {
	ctx := context.Background()
	opt := ArchiveOptions{MaxImageBytes: 300 << 20, Platform: "linux/amd64"}
	amd, arm := twoLayers(t, "amd64", "", "1.2.5-r0"), twoLayers(t, "arm64", "v8", "1.2.5-r9")
	cfg, man := digestOf(t, amd.ConfigName), digestOf(t, amd.Digest)

	docker, size := dockerSave(t, amd, "registry.acme.example/shop:1.0")
	raw, err := ArchiveSBOM(ctx, docker, opt, "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	d := parse(t, raw)
	want := fmt.Sprint(map[string]string{"flawrook:image.keyKind": "config", "flawrook:image.configDigest": cfg, "flawrook:image.platform": "linux/amd64",
		"flawrook:image.sizeBytes": fmt.Sprint(size)})
	if c := d.Metadata.Component; d.SpecVersion != "1.7" || c.Type != "container" || c.Name != "registry.acme.example/shop:1.0" || c.Version != cfg ||
		fmt.Sprint(d.props()) != want || d.packages() != "musl@1.2.5-r0" || d.Metadata.Tools.Components[0].Name != "flawrook-agent" {
		t.Errorf("docker archive: %s %+v %v %s", d.SpecVersion, c, d.props(), d.packages())
	}

	raw, err = ArchiveSBOM(ctx, ociArchive(t, entry{amd, amd64, named}), opt, "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	d = parse(t, raw)
	want = fmt.Sprint(map[string]string{"flawrook:image.keyKind": "manifest", "flawrook:image.configDigest": cfg, "flawrook:image.platform": "linux/amd64",
		"flawrook:image.sizeBytes": fmt.Sprint(compressedSize(t, amd)), "flawrook:image.manifestDigest": man})
	if c := d.Metadata.Component; d.SpecVersion != "1.7" || c.Name != "registry.acme.example/shop:1.0" || c.Version != man || fmt.Sprint(d.props()) != want {
		t.Errorf("OCI archive: %s %+v %v", d.SpecVersion, c, d.props())
	}

	// From an index of two, the platform asked for: its key and its packages.
	both := ociArchive(t, entry{amd, amd64, named}, entry{arm, arm64v8, named})
	for platform, w := range map[string][2]string{"linux/amd64": {man, "musl@1.2.5-r0"}, "linux/arm64": {digestOf(t, arm.Digest), "musl@1.2.5-r9"}} {
		raw, err := ArchiveSBOM(ctx, both, ArchiveOptions{MaxImageBytes: 300 << 20, Platform: platform}, "0.3.0")
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if d := parse(t, raw); d.Metadata.Component.Version != w[0] || d.packages() != w[1] {
			t.Errorf("%s: %s %s", platform, d.Metadata.Component.Version, d.packages())
		}
	}

	// No name in the archive: --ref's, or no SBOM.
	unnamed := ociLayout(t, entry{amd, amd64, nil})
	if raw, err := ArchiveSBOM(ctx, unnamed, ArchiveOptions{MaxImageBytes: 300 << 20, Platform: "linux/amd64", Ref: "acme/shop:2"}, "0.3.0"); err != nil ||
		parse(t, raw).Metadata.Component.Name != "acme/shop:2" {
		t.Errorf("--ref: %v", err)
	}
	if _, err := ArchiveSBOM(ctx, unnamed, opt, "0.3.0"); err == nil || err.Error() != "the archive names no image; give its name with --ref" {
		t.Errorf("no name: %v", err)
	}
}

func TestArchiveSBOMCaps(t *testing.T) {
	ctx := context.Background()
	img := twoLayers(t, "amd64", "", "1.2.5-r0")
	docker, tarSize := dockerSave(t, img, "acme/shop:1")
	oci := ociArchive(t, entry{img, amd64, named})
	gz := compressedSize(t, img)
	var capped *CapError
	for _, tc := range []struct {
		path string
		max  int64
		line string
	}{
		{oci, gz - 1, fmt.Sprintf("too large: %d bytes compressed, the limit is %d", gz, gz-1)},
		{docker, tarSize - 1, fmt.Sprintf("too large: %d bytes uncompressed, the limit is %d", tarSize, tarSize-1)},
	} {
		if _, err := ArchiveSBOM(ctx, tc.path, ArchiveOptions{MaxImageBytes: tc.max, Platform: "linux/amd64"}, "0.3.0"); !errors.As(err, &capped) || capped.Line != tc.line {
			t.Errorf("image cap: %v, want %q", err, tc.line)
		}
		// At the limit, it's read.
		if _, err := ArchiveSBOM(ctx, tc.path, ArchiveOptions{MaxImageBytes: tc.max + 1, Platform: "linux/amd64"}, "0.3.0"); err != nil {
			t.Errorf("at the limit: %v", err)
		}
	}
	defer func(n int) { maxArchiveSBOM = n }(maxArchiveSBOM)
	maxArchiveSBOM = 100
	if _, err := ArchiveSBOM(ctx, oci, ArchiveOptions{MaxImageBytes: 300 << 20, Platform: "linux/amd64"}, "0.3.0"); !errors.As(err, &capped) ||
		capped.Line != "the SBOM is over 20 MiB; split the image or raise the limit on your FlawRook" {
		t.Errorf("SBOM cap: %v", err)
	}
}

// The cluster path's SBOM: CycloneDX 1.7, flawrook-agent as the tool, and only what an image runs: a lockfile's
// packages (Syft's directory catalogers) aren't in it.
func TestTheClusterSBOM(t *testing.T) {
	img := twoLayers(t, "amd64", "", "1.2.5-r0")
	lock, err := crane.Layer(map[string][]byte{"app/package-lock.json": []byte(`{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{` +
		`"":{"name":"app","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if img, err = mutate.AppendLayers(img, lock); err != nil {
		t.Fatal(err)
	}
	raw, packages, err := SBOM(context.Background(), SBOMSource{Tag: "oci-dir", Path: ociLayout(t, entry{img, amd64, nil}), Name: "acme/app:1"}, "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	d := parse(t, raw)
	if d.SpecVersion != "1.7" || d.Metadata.Tools.Components[0].Name != "flawrook-agent" || d.Metadata.Tools.Components[0].Version != "0.3.0" ||
		d.packages() != "musl@1.2.5-r0" || packages != 1 || d.Metadata.Component.Version != digestOf(t, img.Digest) {
		t.Errorf("%s %+v: %s (%d)", d.SpecVersion, d.Metadata.Tools, d.packages(), packages)
	}
}
