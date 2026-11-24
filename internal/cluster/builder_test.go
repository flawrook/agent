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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// setMiB writes a cgroup file whole, as the kernel shows it, so a sample never reads half of it.
func setMiB(t *testing.T, root, name string, mib int64) {
	t.Helper()
	tmp := filepath.Join(root, "."+name)
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", mib<<20)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
}

// buildingImages runs during at the start of each build.
type buildingImages struct {
	fakeImages
	during func()
}

func (b *buildingImages) Build(ctx context.Context, img Image, res Resolved) ([]byte, int, *Status) {
	b.during()
	return b.fakeImages.Build(ctx, img, res)
}

func TestTheBuiltLineCarriesTheBuildsHighestMemory(t *testing.T) {
	root := t.TempDir()
	setMiB(t, root, "memory.current", 100)
	setMiB(t, root, "memory.peak", 1024) // the pod's lifetime peak, from before this build
	images := &buildingImages{during: func() {
		setMiB(t, root, "memory.current", 300)
		time.Sleep(100 * time.Millisecond)
		setMiB(t, root, "memory.current", 50)
		time.Sleep(100 * time.Millisecond)
	}}
	r, _, _ := newRunner(t, webSource("docker.io/library/nginx@"+dA), &images.fakeImages)
	r.Images = images
	r.Memory = CgroupMemory(root, time.Millisecond)
	logs := logged(r)
	if _, err := r.Cycle(context.Background(), OnInterval); err != nil {
		t.Fatal(err)
	}
	if l := line(t, logs, "built"); !strings.HasSuffix(l, " status=uploaded memBuildMaxMiB=300 memCurrentMiB=50 memPeakMiB=1024") {
		t.Fatalf("built line %s", l)
	}
}

func TestTheMemorySamplerStopsWithTheBuild(t *testing.T) {
	root := t.TempDir()
	setMiB(t, root, "memory.current", 100)
	before := runtime.NumGoroutine()
	stop := CgroupMemory(root, time.Millisecond)()
	time.Sleep(20 * time.Millisecond)
	setMiB(t, root, "memory.current", 200)
	time.Sleep(20 * time.Millisecond)
	if got := fmt.Sprint(stop()); got != "[memBuildMaxMiB 200 memCurrentMiB 200]" {
		t.Fatalf("fields %s", got)
	}
	for deadline := time.Now().Add(time.Second); runtime.NumGoroutine() > before; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after the build, %d before", runtime.NumGoroutine(), before)
		}
	}
}

func TestNoMemoryCurrentNoBuildField(t *testing.T) {
	root := t.TempDir()
	setMiB(t, root, "memory.peak", 512)
	stop := CgroupMemory(root, time.Millisecond)()
	time.Sleep(10 * time.Millisecond)
	if got := fmt.Sprint(stop()); got != "[memPeakMiB 512]" {
		t.Fatalf("fields %s", got)
	}
}
