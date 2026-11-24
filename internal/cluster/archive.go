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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/stereoscope/pkg/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ArchiveOptions are the sbom subcommand's flags.
type ArchiveOptions struct {
	MaxImageBytes int64  // the largest image read, by its layers as the archive stores them
	Platform      string // the image to take from an OCI index of several, such as "linux/amd64"
	Ref           string // the image's name when the archive names none
}

// CapError is an image or an SBOM over its limit; its text is the line the subcommand prints.
type CapError struct{ Line string }

func (e *CapError) Error() string { return e.Line }

// The cap line's word for the layers' size: as the archive stores them, compressed or not.
const (
	sizeCompressed   = "compressed"
	sizeUncompressed = "uncompressed"
)

// maxArchiveSBOM is the API's limit on an SBOM, as cluster mode's uploads have it; a variable for the tests.
var maxArchiveSBOM = MaxSBOMBytes

// ArchiveSBOM is the sbom subcommand's work: it reads the archive at p, refuses an image over the cap before
// cataloging it, and answers its CycloneDX SBOM. metadata.component carries the image's name and key, and
// metadata.properties the key's kind, the digests, the platform and the size. It reads no config file and no token,
// and connects to nothing: Syft opens only the archive's own kind of source. An error is a *CapError, or a read or
// catalog error.
func ArchiveSBOM(ctx context.Context, p string, opt ArchiveOptions, version string) ([]byte, error) {
	a, err := ReadArchive(p, opt.Platform)
	if err != nil {
		return nil, err
	}
	if a.SizeBytes > opt.MaxImageBytes {
		word := sizeUncompressed
		if a.Compressed {
			word = sizeCompressed
		}
		return nil, &CapError{fmt.Sprintf("too large: %d bytes %s, the limit is %d", a.SizeBytes, word, opt.MaxImageBytes)}
	}
	name := a.Name
	if name == "" {
		name = opt.Ref
	}
	if name == "" {
		return nil, errors.New("the archive names no image; give its name with --ref")
	}
	src := SBOMSource{Tag: a.Tag, Path: p, Name: name, Key: a.Key(), Properties: []cyclonedx.Property{
		{Name: "flawrook:image.keyKind", Value: a.KeyKind},
		{Name: "flawrook:image.configDigest", Value: a.ConfigDigest},
		{Name: "flawrook:image.platform", Value: a.Platform},
		{Name: "flawrook:image.sizeBytes", Value: strconv.FormatInt(a.SizeBytes, 10)},
	}}
	if a.ManifestDigest != "" {
		src.Properties = append(src.Properties, cyclonedx.Property{Name: "flawrook:image.manifestDigest", Value: a.ManifestDigest})
	}
	if a.Several { // Syft checks a platform against a single image too, so it gets one only for an index of several
		if src.Platform, err = image.NewPlatform(opt.Platform); err != nil {
			return nil, fmt.Errorf("--platform: %w", err)
		}
	}
	sbom, _, err := SBOM(ctx, src, version)
	if err != nil {
		return nil, err
	}
	if len(sbom) > maxArchiveSBOM {
		return nil, &CapError{"the SBOM is over 20 MiB; split the image or raise the limit on your FlawRook"}
	}
	return sbom, nil
}

// Archive is what the sbom subcommand reads of an image on disk before Syft catalogs it: which of Syft's sources
// opens it, the image's key, its platform, and its layers as the archive stores them.
type Archive struct {
	Tag            string // Syft's source: "oci-dir", "oci-archive" or "docker-archive"
	Name           string // the reference the archive names; empty when it names none
	KeyKind        string // "manifest" (OCI: the platform manifest's digest, as a registry shows it) or "config"
	ManifestDigest string // empty for a docker archive, whose manifest is Docker's, not the registry's
	ConfigDigest   string
	Platform       string // os/architecture[/variant], from the image's config
	SizeBytes      int64  // the layers as stored
	Compressed     bool   // every layer is stored compressed (gzip or zstd)
	Several        bool   // an OCI index of several images, of which the platform chose this one
}

// Key is the image's key: the manifest digest of an OCI image, the config digest of a docker archive's.
func (a Archive) Key() string {
	if a.KeyKind == "manifest" {
		return a.ManifestDigest
	}
	return a.ConfigDigest
}

// ErrNotAnArchive is an input that is neither a Docker nor an OCI archive, nor an OCI layout directory.
var ErrNotAnArchive = errors.New("not a Docker or OCI archive")

// The largest file kept whole while the tar is read: index.json, manifest.json, image manifests and configs.
const smallFile = 1 << 20

// files is an archive's content by name: whole for small files, the size and first bytes for the rest.
type files struct {
	whole map[string][]byte
	size  map[string]int64
	head  map[string][]byte
}

func (f files) read(name string) ([]byte, error) {
	if b, ok := f.whole[name]; ok {
		return b, nil
	}
	if _, ok := f.size[name]; ok {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, smallFile)
	}
	return nil, fmt.Errorf("%s is missing", name)
}

// ReadArchive reads an image archive: a directory is an OCI layout (oci-dir); a tar with Docker's manifest.json is a
// docker archive, a modern `docker save` that also carries an OCI index.json included; a tar with only index.json is
// an OCI archive. platform ("linux/amd64") chooses among the images of an OCI index of several; an index of one
// image isn't checked against it.
func ReadArchive(p, platform string) (Archive, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return Archive{}, err
	}
	var f files
	if fi.IsDir() {
		f, err = readDir(p)
	} else {
		f, err = readTar(p)
	}
	if err != nil {
		return Archive{}, err
	}
	switch _, docker := f.size["manifest.json"]; {
	case fi.IsDir():
		if _, ok := f.size["index.json"]; !ok {
			return Archive{}, ErrNotAnArchive
		}
		return readOCI(f, "oci-dir", platform)
	case docker:
		return readDocker(f)
	default:
		if _, ok := f.size["index.json"]; !ok {
			return Archive{}, ErrNotAnArchive
		}
		return readOCI(f, "oci-archive", platform)
	}
}

func newFiles() files {
	return files{whole: map[string][]byte{}, size: map[string]int64{}, head: map[string][]byte{}}
}

func readTar(p string) (files, error) {
	in, err := os.Open(p)
	if err != nil {
		return files{}, err
	}
	defer in.Close()
	f := newFiles()
	tr := tar.NewReader(in)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(f.size) == 0 {
				return files{}, ErrNotAnArchive
			}
			return files{}, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if err := f.add(name, h.Size, tr); err != nil {
			return files{}, err
		}
	}
	return f, nil
}

func readDir(dir string) (files, error) {
	f := newFiles()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		rel, _ := filepath.Rel(dir, p)
		return f.add(filepath.ToSlash(rel), info.Size(), in)
	})
	return f, err
}

func (f files) add(name string, size int64, r io.Reader) error {
	f.size[name] = size
	if size <= smallFile {
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		f.whole[name], f.head[name] = b, b[:min(len(b), 4)]
		return nil
	}
	head := make([]byte, 4)
	n, err := io.ReadFull(r, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	f.head[name] = head[:n]
	return nil
}

func readDocker(f files) (Archive, error) {
	raw, err := f.read("manifest.json")
	if err != nil {
		return Archive{}, err
	}
	var m tarball.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Archive{}, fmt.Errorf("manifest.json: %w", err)
	}
	if len(m) != 1 {
		return Archive{}, fmt.Errorf("the archive holds %d images; save one", len(m))
	}
	config, err := f.read(m[0].Config)
	if err != nil {
		return Archive{}, err
	}
	sum := sha256.Sum256(config)
	a := Archive{Tag: "docker-archive", KeyKind: "config", ConfigDigest: "sha256:" + hex.EncodeToString(sum[:]), Compressed: true}
	if len(m[0].RepoTags) > 0 {
		a.Name = m[0].RepoTags[0]
	}
	if a.Platform, err = platformOf(config); err != nil {
		return Archive{}, err
	}
	// Docker's manifest.json says nothing of the layers' compression; their first bytes do.
	for _, l := range m[0].Layers {
		size, ok := f.size[l]
		if !ok {
			return Archive{}, fmt.Errorf("%s is missing", l)
		}
		a.SizeBytes += size
		a.Compressed = a.Compressed && compressed(f.head[l])
	}
	return a, nil
}

// compressed says a layer's first bytes are gzip's or zstd's magic number.
func compressed(head []byte) bool {
	return bytes.HasPrefix(head, []byte{0x1f, 0x8b}) || bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd})
}

// anImage is an image manifest an OCI index names, with the platforms its entries give and the name they carry.
type anImage struct {
	digest    string
	platforms []v1.Platform
	name      string
}

func readOCI(f files, tag, platform string) (Archive, error) {
	raw, err := f.read("index.json")
	if err != nil {
		return Archive{}, err
	}
	var images []anImage
	if err := walkIndex(f, raw, "", &images); err != nil {
		return Archive{}, err
	}
	var chosen *anImage
	switch len(images) {
	case 0:
		return Archive{}, errors.New("the archive's index names no image")
	case 1:
		chosen = &images[0]
	default:
		want, err := v1.ParsePlatform(platform)
		if err != nil {
			return Archive{}, fmt.Errorf("--platform: %w", err)
		}
		var have []string
		for i, img := range images {
			for _, p := range img.platforms {
				have = append(have, p.String())
				if p.OS == want.OS && p.Architecture == want.Architecture && (want.Variant == "" || p.Variant == want.Variant) {
					if chosen != nil && chosen.digest != img.digest {
						return Archive{}, fmt.Errorf("the archive holds several images for %s", platform)
					}
					chosen = &images[i]
				}
			}
		}
		if chosen == nil {
			return Archive{}, fmt.Errorf("the archive holds no image for %s, only for %s", platform, strings.Join(slices.Compact(slices.Sorted(slices.Values(have))), ", "))
		}
	}
	raw, err = f.read(blob(chosen.digest))
	if err != nil {
		return Archive{}, err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return Archive{}, fmt.Errorf("manifest %s: %w", chosen.digest, err)
	}
	config, err := f.read(blob(m.Config.Digest.String()))
	if err != nil {
		return Archive{}, err
	}
	a := Archive{Tag: tag, Name: chosen.name, KeyKind: "manifest", ManifestDigest: chosen.digest, ConfigDigest: m.Config.Digest.String(),
		Compressed: true, Several: len(images) > 1}
	if a.Platform, err = platformOf(config); err != nil {
		return Archive{}, err
	}
	for _, l := range m.Layers {
		a.SizeBytes += l.Size
		mt := string(l.MediaType)
		a.Compressed = a.Compressed && (strings.HasSuffix(mt, "gzip") || strings.HasSuffix(mt, "zstd"))
	}
	return a, nil
}

// walkIndex collects the image manifests an index names, through nested indexes, as stereoscope does: attestation
// manifests left out, each image once with every platform its entries give.
func walkIndex(f files, raw []byte, name string, images *[]anImage) error {
	idx, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	for _, d := range idx.Manifests {
		n := name
		if v := d.Annotations["io.containerd.image.name"]; v != "" {
			n = v
		}
		switch {
		case d.MediaType.IsIndex():
			nested, err := f.read(blob(d.Digest.String()))
			if err != nil {
				return err
			}
			if err := walkIndex(f, nested, n, images); err != nil {
				return err
			}
		case d.MediaType.IsImage():
			if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" || (d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown") {
				continue
			}
			i := slices.IndexFunc(*images, func(img anImage) bool { return img.digest == d.Digest.String() })
			if i < 0 {
				*images = append(*images, anImage{digest: d.Digest.String(), name: n})
				i = len(*images) - 1
			}
			if d.Platform != nil {
				(*images)[i].platforms = append((*images)[i].platforms, *d.Platform)
			}
		}
	}
	return nil
}

func blob(digest string) string {
	algo, hash, _ := strings.Cut(digest, ":")
	return "blobs/" + algo + "/" + hash
}

func platformOf(config []byte) (string, error) {
	c, err := v1.ParseConfigFile(bytes.NewReader(config))
	if err != nil {
		return "", fmt.Errorf("the image's config: %w", err)
	}
	p := c.OS + "/" + c.Architecture
	if c.Variant != "" {
		p += "/" + c.Variant
	}
	return p, nil
}
