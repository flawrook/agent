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

// Package mounts says which mount points the inventory doesn't walk: network filesystems and FUSE mounts
// (a big share is slow to walk and costly to index, and its files aren't this host's packages), unless
// the config's include_mounts names them. Read from the mount table, /proc/self/mountinfo.
package mounts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The skipped filesystem types: NFS, SMB, and every FUSE filesystem (sshfs, rclone, s3fs, ...).
var networkTypes = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true}

func skippedType(fsType string) bool {
	return networkTypes[fsType] || strings.HasPrefix(fsType, "fuse.")
}

// Mount is one line of the mount table: where it is mounted, and its filesystem type.
type Mount struct {
	Point string
	Type  string
}

// Read reads this process's mount table; none when it can't be read.
func Read() []Mount {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return Parse(string(raw))
}

// Parse reads mountinfo (proc(5)): the mount point is the fifth field, the filesystem type the first
// one after the " - " separator. Spaces and the like in a mount point are octal escapes (\040).
func Parse(text string) []Mount {
	var out []Mount
	for _, line := range strings.Split(text, "\n") {
		before, after, ok := strings.Cut(line, " - ")
		fields, rest := strings.Fields(before), strings.Fields(after)
		if !ok || len(fields) < 5 || len(rest) < 1 {
			continue
		}
		out = append(out, Mount{Point: unescape(fields[4]), Type: rest[0]})
	}
	return out
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Skipped are the mount points of network and FUSE filesystems, less those include names (exactly, as
// absolute paths). The root filesystem is never skipped, whatever it is.
func Skipped(table []Mount, include []string) []string {
	keep := map[string]bool{}
	for _, p := range include {
		keep[filepath.Clean(p)] = true
	}
	var out []string
	for _, m := range table {
		point := filepath.Clean(m.Point)
		if point != "/" && skippedType(m.Type) && !keep[point] {
			out = append(out, point)
		}
	}
	return out
}

// Patterns turns mount points into the inventory's exclusions, relative to the scanned root ("./mnt/nfs/**"),
// with the glob's special characters escaped.
func Patterns(points []string) []string {
	out := make([]string, 0, len(points))
	for _, p := range points {
		var b strings.Builder
		for _, r := range strings.TrimPrefix(p, "/") {
			if strings.ContainsRune(`\*?[]{}`, r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		out = append(out, "./"+b.String()+"/**")
	}
	return out
}
