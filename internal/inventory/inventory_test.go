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

package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"flawrook.dev/agent/internal/mounts"
)

func dpkgStatus(pkg, source, version string) string {
	return "Package: " + pkg + "\nStatus: install ok installed\nArchitecture: arm64\nSource: " + source + "\nVersion: " + version + "\nDescription: test\n"
}

// A Debian 12 root with one package, and dpkg databases where the agent must not look: an image layer
// in Docker's storage, and /tmp.
func TestBuildCatalogsTheHostAndSkipsContainerStorage(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n",
		"var/lib/dpkg/status": dpkgStatus("libssl3", "openssl", "3.0.15-1~deb12u1"),
		"var/lib/docker/overlay2/abc/diff/var/lib/dpkg/status":                  dpkgStatus("nginx", "nginx", "1.22.1-9"),
		"var/lib/containerd/io.containerd.snapshotter/1/fs/var/lib/dpkg/status": dpkgStatus("redis", "redis", "5:7.0.15-1"),
		"tmp/unpacked/var/lib/dpkg/status":                                      dpkgStatus("curl", "curl", "7.88.1-10"),
	}
	for rel, text := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, stats, err := Build(context.Background(), root, "0.1.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name, Version, Purl string
			Type                string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var purls []string
	for _, c := range doc.Components {
		if c.Type == "file" {
			t.Fatalf("a file component: %+v (WithoutFiles)", c)
		}
		if c.Type != "operating-system" {
			purls = append(purls, c.Purl)
		}
	}
	if doc.BOMFormat != "CycloneDX" || len(purls) != 1 || !strings.HasPrefix(purls[0], "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?") || !strings.Contains(purls[0], "upstream=openssl") || !strings.Contains(purls[0], "distro=debian-12") {
		t.Fatalf("components %v", purls)
	}
	if stats.Packages != 1 {
		t.Errorf("stats %+v", stats)
	}
	// Syft lists its file catalogers too; WithoutFiles leaves them nothing to catalog.
	var used []string
	for _, name := range stats.Used {
		if !strings.HasPrefix(name, "file-") {
			used = append(used, name)
		}
	}
	sort.Strings(used)
	// The brief's list, written out: dpkg, rpm, apk, binary-classifier and PHP's interpreter, nothing else.
	want := []string{"apk-db-cataloger", "binary-classifier-cataloger", "dpkg-db-cataloger", "php-interpreter-cataloger", "rpm-db-cataloger"}
	if !reflect.DeepEqual(used, want) {
		t.Fatalf("catalogers used %v, want %v", used, want)
	}
	for _, name := range stats.Used {
		if name == "linux-kernel-cataloger" {
			t.Fatal("the linux-kernel cataloger ran: the report's kernel is the running one")
		}
	}
}

// The CTO's case: a host whose mount table has an NFS share and an sshfs mount (not walked) and an NFS
// mount listed in include_mounts (walked). Each holds a dpkg database a walk would find.
func TestNetworkMountsAreNotWalkedButIncludedOnesAre(t *testing.T) {
	root := t.TempDir()
	for rel, text := range map[string]string{
		"etc/os-release":                      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status":                 dpkgStatus("libssl3", "openssl", "3.0.15-1~deb12u1"),
		"mnt/nfs/chroot/var/lib/dpkg/status":  dpkgStatus("nginx", "nginx", "1.22.1-9"),
		"home/ops/remote/var/lib/dpkg/status": dpkgStatus("curl", "curl", "7.88.1-10"),
		"srv/data/jail/var/lib/dpkg/status":   dpkgStatus("bash", "bash", "5.2.15-2+b7"),
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	table := mounts.Parse(`22 1 259:2 / / rw - ext4 /dev/vda1 rw
40 22 0:45 / /mnt/nfs rw - nfs4 fileserver:/export rw
41 22 0:46 / /home/ops/remote rw - fuse.sshfs ops@backup:/data rw
43 22 0:48 / /srv/data rw - nfs nas:/data rw
`)
	raw, _, err := Build(context.Background(), root, "0.1.0", mounts.Patterns(mounts.Skipped(table, []string{"/srv/data"})))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct{ Name string } `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range doc.Components {
		if c.Name != "debian" {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"bash", "libssl3"}) {
		t.Fatalf("packages %v: want the host's and the included mount's, not the NFS or sshfs ones", names)
	}
}
