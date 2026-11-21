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
	"os"
	"path"
	"path/filepath"
	"strings"

	"flawrook.dev/agent/internal/mounts"
)

// Read are the paths the catalogers read: the release files (all of /etc, which is small), the package
// databases, and the directories where runtimes live. Everything else under the root is excluded, and Syft
// skips an excluded directory whole, so its index, most of a scan's memory, holds these trees only. 0.1.0
// indexed all of / and reached 508 MiB on a host with large application trees.
var Read = []string{
	"/etc",
	"/var/lib/dpkg", "/var/lib/rpm", "/var/lib/rpmmanifest", "/lib/apk/db", // /usr/lib/sysimage/rpm is in /usr/lib
	"/bin", "/sbin", "/lib", // real directories where /usr isn't merged (Alpine), symlinks into /usr elsewhere
	"/usr/bin", "/usr/sbin", "/usr/lib",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/usr/local/go", // runtimes from tarballs: Go, a global npm, PHP's extensions
	"/opt",
}

// Heavy are application trees inside those directories, which hold no runtime the catalogers look for.
var Heavy = []string{"**/node_modules", "**/.git", "**/__pycache__", "**/site-packages", "**/dist-packages"}

// Narrow returns the exclusions that leave only Read and include (mount points walked all the same) under
// root: at each directory on the way to one of them, every other entry; and the Heavy trees everywhere. A
// symlink on the way isn't followed, but where an allowed path runs through one (/var a link to /data/var),
// the path it resolves to is allowed too, that chain only (/data/var/lib/dpkg, not the rest of /data). A
// directory that can't be read is left as it is.
func Narrow(root string, include []string) []string {
	allowed := append(append([]string(nil), Read...), include...)
	for _, a := range allowed[:len(allowed):len(allowed)] {
		if r := resolved(root, a); r != "" {
			allowed = append(allowed, r)
		}
	}
	var out []string
	var walk func(dir string)
	walk = func(dir string) {
		keep := map[string]bool{}
		for _, a := range allowed {
			if a == dir || strings.HasPrefix(dir, a+"/") {
				return // all of dir is read
			}
			if rest, ok := strings.CutPrefix(a, strings.TrimSuffix(dir, "/")+"/"); ok {
				keep[strings.SplitN(rest, "/", 2)[0]] = true
			}
		}
		entries, err := os.ReadDir(path.Join(root, dir))
		if err != nil {
			return
		}
		for _, e := range entries {
			p := path.Join(dir, e.Name())
			switch {
			case !keep[e.Name()]:
				out = append(out, "./"+mounts.Escape(strings.TrimPrefix(p, "/")))
			case e.IsDir():
				walk(p)
			}
		}
	}
	walk("/")
	return append(out, Heavy...)
}

// resolved is the allowed path a with the symlinks on its way resolved, as the root's own path; the part past
// what exists stays as written. It is "" when nothing on the way is a link, or when a link leads out of root.
func resolved(root, a string) string {
	for p, rest := a, ""; p != "/"; p, rest = path.Dir(p), path.Join(path.Base(p), rest) {
		real, err := filepath.EvalSymlinks(filepath.Join(root, p))
		if err != nil {
			continue // not there (yet): try the directory above
		}
		base, err := filepath.EvalSymlinks(root)
		if err != nil {
			return ""
		}
		rel, err := filepath.Rel(base, real)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return ""
		}
		if r := path.Join("/", filepath.ToSlash(rel), rest); r != a {
			return r
		}
		return ""
	}
	return ""
}
