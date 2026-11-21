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
	"time"

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

// writeTree writes files under root, and the symlinks given as "link -> target".
func writeTree(t *testing.T, root string, files map[string]string, links ...string) {
	t.Helper()
	for rel, text := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range links {
		link, target, _ := strings.Cut(l, " -> ")
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
}

// 0.2.0, the review's memory finding: only what the catalogers read is left to walk. A merged /usr's /lib is
// a symlink, kept and not followed; a name with glob characters is excluded as written; include_mounts keeps
// its mount point and nothing else beside it.
func TestNarrowExcludesAllButWhatTheCatalogersRead(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release": "ID=debian\n", "etc/ssl/certs/a.pem": "x",
		"home/u/a": "x", "root/a": "x", "snap/a": "x", "srv/www/a": "x", "srv/data/a": "x", "srv/notes": "x", "we[ird]/a": "x",
		"var/lib/dpkg/status": "x", "var/lib/postgresql/16/main/base/1": "x", "var/lib/docker/a": "x", "var/log/syslog": "x", "var/cache/a": "x",
		"usr/bin/node": "x", "usr/lib/x86_64-linux-gnu/libc.so.6": "x", "usr/share/doc/a/copyright": "x", "usr/src/linux/Makefile": "x", "usr/include/a.h": "x",
		"usr/local/bin/node": "x", "usr/local/go/bin/go": "x", "usr/local/lib/node_modules/npm/a": "x", "usr/local/share/a": "x", "usr/local/src/a": "x",
		"opt/app/node_modules/a/b": "x",
	}, "lib -> usr/lib", "bin -> usr/bin")
	got := Narrow(root, []string{"/srv/data"})
	sort.Strings(got)
	want := append([]string{
		"./home", "./root", "./snap", "./srv/notes", "./srv/www", `./we\[ird\]`,
		"./usr/include", "./usr/local/share", "./usr/local/src", "./usr/share", "./usr/src",
		"./var/cache", "./var/lib/docker", "./var/lib/postgresql", "./var/log",
	}, Heavy...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exclusions\n got %q\nwant %q", got, want)
	}
}

// The scan with those exclusions: the host's package and the runtimes where they live are found; a dpkg
// database and node binaries in a home, a web root and an app's node_modules are not, nor anything in
// /usr/src; an included mount is.
func TestNarrowedScanFindsTheHostButNotApplicationTrees(t *testing.T) {
	root := t.TempDir()
	node := func(v string) string { return "\x7fELF....node.js/v" + v + "\x00" }
	writeTree(t, root, map[string]string{
		"etc/os-release":                     "ID=debian\nVERSION_ID=\"13\"\n",
		"var/lib/dpkg/status":                dpkgStatus("libssl3t64", "openssl", "3.5.4-1~deb13u1"),
		"usr/local/bin/node":                 node("22.11.0"),
		"opt/nodejs/bin/node":                node("20.18.1"),
		"srv/data/tools/bin/node":            node("18.20.5"), // an included mount
		"home/u/.nvm/versions/node/bin/node": node("16.20.2"),
		"home/u/chroot/var/lib/dpkg/status":  dpkgStatus("curl", "curl", "8.14.1-2"),
		"var/www/site/bin/node":              node("14.21.3"),
		"opt/app/node_modules/.bin/node":     node("12.22.12"),
		"usr/src/linux/tools/node":           node("10.24.1"),
	})
	raw, _, err := Build(context.Background(), root, "0.2.0", Narrow(root, []string{"/srv/data"}))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct{ Name, Version, Type string } `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, c := range doc.Components {
		if c.Type != "operating-system" {
			found = append(found, c.Name+" "+c.Version)
		}
	}
	sort.Strings(found)
	want := []string{"libssl3t64 3.5.4-1~deb13u1", "node 18.20.5", "node 20.18.1", "node 22.11.0"}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("found %q, want %q", found, want)
	}
}

func TestStatsLine(t *testing.T) {
	for _, c := range []struct {
		s    Stats
		want string
	}{
		{Stats{Packages: 335, Elapsed: 28*time.Second + 400*time.Millisecond, MaxRSSKiB: 122880}, "scan 28 s, 335 packages, peak 120 MiB"},
		{Stats{Packages: 1, Elapsed: 2340 * time.Millisecond, MaxRSSKiB: 1}, "scan 2.3 s, 1 package, peak 0 MiB"},
	} {
		if got := c.s.Line(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
}

// /var a symlink to /data/var: the allowed paths through it are resolved and allowed, that chain only. The dpkg
// database behind the link is found, as 0.1.0 found it; the rest of /data, a backup's database among it, is not
// walked, and neither is the link.
func TestNarrowFollowsAnAllowedPathThroughASymlinkOnly(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":                       "ID=debian\nVERSION_ID=\"12\"\n",
		"data/var/lib/dpkg/status":             dpkgStatus("libssl3", "openssl", "3.0.15-1~deb12u1"),
		"data/var/lib/mysql/ibdata1":           "x",
		"data/var/log/syslog":                  "x",
		"data/backups/var/lib/dpkg/status":     dpkgStatus("curl", "curl", "7.88.1-10"),
		"data/backups/usr/local/bin/README.md": "x",
	}, "var -> data/var")
	got := Narrow(root, nil)
	sort.Strings(got)
	want := append([]string{"./data/backups", "./data/var/lib/mysql", "./data/var/log"}, Heavy...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exclusions\n got %q\nwant %q", got, want)
	}
	raw, _, err := Build(context.Background(), root, "0.2.0", got)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct{ Name, Type string } `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range doc.Components {
		if c.Type != "operating-system" {
			names = append(names, c.Name)
		}
	}
	if !reflect.DeepEqual(names, []string{"libssl3"}) {
		t.Fatalf("packages %v: want the one behind /var, not the backup's", names)
	}
}

// A symlink on the way that leads out of root allows nothing inside it: here /opt points at a sibling of the
// root named escape, and the root's own /escape stays excluded.
func TestNarrowIgnoresASymlinkOutOfRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	writeTree(t, parent, map[string]string{"escape/lib/a": "x", "root/etc/os-release": "ID=debian\n", "root/escape/lib/b": "x"})
	if err := os.Symlink(filepath.Join(parent, "escape"), filepath.Join(root, "opt")); err != nil {
		t.Fatal(err)
	}
	got := Narrow(root, nil)
	sort.Strings(got)
	want := append([]string{"./escape"}, Heavy...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exclusions\n got %q\nwant %q", got, want)
	}
}
