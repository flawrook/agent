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

// Package hostinfo reads what the report says about the host besides its packages: its identity,
// hostname, running kernel and os-release.
package hostinfo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// AppID is FlawRook's agent app id (852f4940-356a-4c1f-9a7a-461ded34e665), fixed for good and published:
// hostId = HMAC-SHA256(key: the machine id's 16 bytes, message: these 16 bytes), the way systemd's
// sd_id128_get_machine_app_specific derives an app-specific id. Never the token, so rotating a token
// never makes a host a new entry, and the raw machine id never leaves the host.
var AppID = [16]byte{0x85, 0x2f, 0x49, 0x40, 0x35, 0x6a, 0x4c, 0x1f, 0x9a, 0x7a, 0x46, 0x1d, 0xed, 0x34, 0xe6, 0x65}

// The sources of the machine id, in order, as host.hostIdSource names them.
const (
	SourceMachineID     = "machine-id"
	SourceDbusMachineID = "dbus-machine-id"
	SourceGenerated     = "generated"
)

// Info is the report's "host".
type Info struct {
	HostID       string            `json:"hostId"`
	HostIDSource string            `json:"hostIdSource"`
	Hostname     string            `json:"hostname"`
	Kernel       string            `json:"kernel"`
	OSRelease    map[string]string `json:"osRelease"`
}

// Reader reads the host under Root ("/" on a host; a directory in tests). StateDir keeps the
// generated id (/var/lib/flawrook, the systemd unit's StateDirectory).
type Reader struct {
	Root     string
	StateDir string
	Uname    func() (string, error) // the running kernel's release
	Hostname func() (string, error)
}

// New reads the real host.
func New() Reader {
	return Reader{Root: "/", StateDir: "/var/lib/flawrook", Uname: uname, Hostname: os.Hostname}
}

// Read gathers the host's facts. hostname, when set, overrides the real hostname (decision 6).
func (r Reader) Read(hostname string) (Info, error) {
	id, source, err := r.HostID()
	if err != nil {
		return Info{}, err
	}
	if hostname == "" {
		if hostname, err = r.Hostname(); err != nil {
			return Info{}, fmt.Errorf("hostname: %w", err)
		}
	}
	return Info{HostID: id, HostIDSource: source, Hostname: hostname, Kernel: r.Kernel(), OSRelease: r.OSRelease()}, nil
}

// Kernel is the running kernel's release: uname -r, else /proc/sys/kernel/osrelease, else "".
func (r Reader) Kernel() string {
	if release, err := r.Uname(); err == nil && strings.TrimSpace(release) != "" {
		return strings.TrimSpace(release)
	}
	if raw, err := os.ReadFile(r.path("proc/sys/kernel/osrelease")); err == nil {
		return strings.TrimSpace(string(raw))
	}
	return ""
}

func uname() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

// OSRelease is every KEY=value of /etc/os-release, else /usr/lib/os-release; empty when neither exists.
func (r Reader) OSRelease() map[string]string {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if raw, err := os.ReadFile(r.path(p)); err == nil {
			return ParseOSRelease(string(raw))
		}
	}
	return map[string]string{}
}

var osReleaseKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseOSRelease reads os-release(5): KEY=value lines, comments and blank lines skipped, a value in
// single or double quotes unquoted, and in double quotes the escapes \" \\ \$ \` undone.
func ParseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || !osReleaseKey.MatchString(key) {
			continue
		}
		if n := len(value); n >= 2 && (value[0] == '"' || value[0] == '\'') && value[n-1] == value[0] {
			quote := value[0]
			value = value[1 : n-1]
			if quote == '"' {
				var b strings.Builder
				for i := 0; i < len(value); i++ {
					if value[i] == '\\' && i+1 < len(value) && strings.IndexByte("\"\\$`", value[i+1]) >= 0 {
						i++
					}
					b.WriteByte(value[i])
				}
				value = b.String()
			}
		}
		out[key] = value
	}
	return out
}

var machineIDFormat = regexp.MustCompile(`^[0-9a-f]{32}$`)

// HostID derives the host's id from the first valid machine id: /etc/machine-id, then
// /var/lib/dbus/machine-id, else one generated once and kept in StateDir/host-id. A machine id that
// isn't 32 hex characters (empty, "uninitialized", all zeros) counts as missing.
func (r Reader) HostID() (id, source string, err error) {
	for _, s := range []struct{ path, source string }{
		{r.path("etc/machine-id"), SourceMachineID},
		{r.path("var/lib/dbus/machine-id"), SourceDbusMachineID},
	} {
		if m, ok := readMachineID(s.path); ok {
			return derive(m), s.source, nil
		}
	}
	keep := filepath.Join(r.StateDir, "host-id")
	if m, ok := readMachineID(keep); ok {
		return derive(m), SourceGenerated, nil
	}
	var m [16]byte
	if _, err := rand.Read(m[:]); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return "", "", fmt.Errorf("no machine id, and the generated one can't be kept: %w", err)
	}
	if err := os.WriteFile(keep, []byte(hex.EncodeToString(m[:])+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("no machine id, and the generated one can't be kept: %w", err)
	}
	return derive(m), SourceGenerated, nil
}

func readMachineID(path string) ([16]byte, bool) {
	var m [16]byte
	raw, err := os.ReadFile(path)
	text := strings.TrimSpace(string(raw))
	if err != nil || !machineIDFormat.MatchString(text) || text == strings.Repeat("0", 32) {
		return m, false
	}
	_, _ = hex.Decode(m[:], []byte(text))
	return m, true
}

func derive(machineID [16]byte) string {
	mac := hmac.New(sha256.New, machineID[:])
	mac.Write(AppID[:])
	return hex.EncodeToString(mac.Sum(nil))
}

func (r Reader) path(rel string) string { return filepath.Join(r.Root, rel) }
