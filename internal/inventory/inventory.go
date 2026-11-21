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

// Package inventory builds the host's CycloneDX SBOM with Syft as a library: the OS package databases
// and the runtimes found by their binaries, nothing from the network.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"syscall"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	_ "modernc.org/sqlite" // the rpm cataloger reads RHEL 9's rpmdb.sqlite through database/sql, as Syft's CLI registers it
)

// Catalogers: dpkg, rpm and apk databases, runtimes by their binaries (Node.js, Python, nginx, Redis,
// ...), and PHP's interpreter. Application lockfiles stay the repository side's job; the
// linux-kernel cataloger is off, the running kernel is the report's "kernel".
var Catalogers = []string{
	"dpkg-db-cataloger",
	"rpm-db-cataloger",
	"apk-db-cataloger",
	"binary-classifier-cataloger",
	"php-interpreter-cataloger",
}

// Skip: pseudo filesystems, temporary files, and container storage, whose images aren't the host's
// packages (images are phase 2). Syft also skips proc, sysfs and devtmpfs mounts on its own.
var Skip = []string{
	"./proc/**", "./sys/**", "./dev/**", "./run/**", "./tmp/**", "./var/tmp/**",
	"./var/lib/docker/**", "./var/lib/containerd/**", "./var/lib/containers/**", "./var/lib/kubelet/**",
}

// Stats are one scan's measures, for the log.
type Stats struct {
	Packages  int
	Elapsed   time.Duration
	MaxRSSKiB int64 // the process's peak so far
	Used      []string
}

// Line is the scan in words, for the journal: "scan 28 s, 335 packages, peak 120 MiB". The peak is the
// process's so far.
func (s Stats) Line() string {
	secs := s.Elapsed.Seconds()
	took := fmt.Sprintf("%.0f s", secs)
	if secs < 10 {
		took = fmt.Sprintf("%.1f s", secs)
	}
	packages := "packages"
	if s.Packages == 1 {
		packages = "package"
	}
	return fmt.Sprintf("scan %s, %d %s, peak %d MiB", took, s.Packages, packages, (s.MaxRSSKiB+512)/1024)
}

// Build scans the filesystem under root and returns Syft's CycloneDX JSON. skip adds exclusions to Skip,
// in its form ("./mnt/nfs/**": the mounts package's network and FUSE mounts).
func Build(ctx context.Context, root, version string, skip []string) ([]byte, Stats, error) {
	start := time.Now()
	src, err := directorysource.New(directorysource.Config{Path: root, Exclude: source.ExcludeConfig{Paths: append(append([]string(nil), Skip...), skip...)}})
	if err != nil {
		return nil, Stats{}, err
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("flawrook-agent", version).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(Catalogers...)).
		WithoutFiles()
	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, Stats{}, err
	}
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, Stats{}, err
	}
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *s); err != nil {
		return nil, Stats{}, err
	}
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return buf.Bytes(), Stats{Packages: s.Artifacts.Packages.PackageCount(), Elapsed: time.Since(start), MaxRSSKiB: ru.Maxrss, Used: used(s.Descriptor.Configuration)}, nil
}

// used reads the catalogers Syft ran from its configuration audit trail.
func used(configuration any) []string {
	raw, _ := json.Marshal(configuration)
	var trail struct {
		Catalogers struct {
			Used []string `json:"used"`
		} `json:"catalogers"`
	}
	_ = json.Unmarshal(raw, &trail)
	return trail.Catalogers.Used
}
