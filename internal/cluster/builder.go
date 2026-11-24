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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Builder is Images over the registry and Syft: each image is downloaded into an OCI layout under TempDir (TMPDIR,
// the chart's size-capped emptyDir), catalogued, and removed.
type Builder struct {
	Registry *Registry
	TempDir  string
	Version  string
}

func (b *Builder) Round() (bool, string) { return b.Registry.Round() }

func (b *Builder) Resolve(ctx context.Context, img Image) (Resolved, *Status) {
	return b.Registry.Resolve(ctx, img)
}

func (b *Builder) Build(ctx context.Context, img Image, res Resolved) ([]byte, int, *Status) {
	dir, err := os.MkdirTemp(b.TempDir, "image-")
	if err != nil {
		return nil, 0, &Status{Status: Error, Reason: "pull-failed", Detail: detail(err)}
	}
	defer os.RemoveAll(dir)
	if st := b.Registry.Download(ctx, res, filepath.Join(dir, "layout")); st != nil {
		return nil, 0, st
	}
	sbom, packages, err := SBOM(ctx, SBOMSource{Tag: "oci-dir", Path: filepath.Join(dir, "layout"), Name: img.Ref}, b.Version)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, 0, &Status{Status: Error, Reason: "timeout", Detail: "the build ran out of time"}
		}
		return nil, 0, &Status{Status: Error, Reason: "catalog-failed", Detail: detail(err)}
	}
	return sbom, packages, nil
}

// CgroupMemory reads the container's cgroup v2 memory for each build's built line. Started as a build starts, it reads
// memory.current every period until the func it returns is called. That func stops it and gives memBuildMaxMiB, the
// highest value read (with builds at once, it covers them all), then what the files say when the build ends: current,
// peak (the pod's lifetime peak), and the anon/file split (page cache counts towards the limit too). Nothing for a
// file that isn't there.
func CgroupMemory(root string, every time.Duration) func() func() []any {
	return func() func() []any {
		high := int64(-1)
		sample := func() {
			if n, ok := readInt(filepath.Join(root, "memory.current")); ok {
				high = max(high, n)
			}
		}
		sample()
		done, stopped := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(stopped)
			tick := time.NewTicker(every)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					sample()
				}
			}
		}()
		return func() []any {
			close(done)
			<-stopped
			var out []any
			if high >= 0 {
				out = append(out, "memBuildMaxMiB", high>>20)
			}
			return append(out, cgroupMemory(root)...)
		}
	}
}

// cgroupMemory reads the cgroup's memory files once.
func cgroupMemory(root string) []any {
	var out []any
	for _, f := range []struct{ file, key string }{{"memory.current", "memCurrentMiB"}, {"memory.peak", "memPeakMiB"}} {
		if n, ok := readInt(filepath.Join(root, f.file)); ok {
			out = append(out, f.key, n>>20)
		}
	}
	if f, err := os.Open(filepath.Join(root, "memory.stat")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), " ")
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && (k == "anon" || k == "file") {
				out = append(out, "mem"+strings.ToUpper(k[:1])+k[1:]+"MiB", n>>20)
			}
		}
	}
	return out
}

// MemoryLimit is 75 % of the cgroup's memory.max, for GOMEMLIMIT when it isn't set; 0 when there is no limit.
func MemoryLimit(root string) int64 {
	n, ok := readInt(filepath.Join(root, "memory.max"))
	if !ok || n <= 0 {
		return 0
	}
	return n / 4 * 3
}

func readInt(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return n, err == nil
}
