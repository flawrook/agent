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

package hostinfo

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A host laid out under a temporary root.
func fakeHost(t *testing.T, files map[string]string) Reader {
	t.Helper()
	root := t.TempDir()
	for rel, text := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Reader{
		Root:     root,
		StateDir: filepath.Join(root, "var/lib/flawrook"),
		Uname:    func() (string, error) { return "", errors.New("no uname here") },
		Hostname: func() (string, error) { return "real-host", nil },
	}
}

func TestKernelFromUnameElseProcElseEmpty(t *testing.T) {
	proc := map[string]string{"proc/sys/kernel/osrelease": "6.1.0-47-arm64\n"}

	r := fakeHost(t, proc)
	r.Uname = func() (string, error) { return "6.8.0-31-generic", nil }
	if got := r.Kernel(); got != "6.8.0-31-generic" {
		t.Errorf("uname: %q", got)
	}
	r.Uname = func() (string, error) { return "", errors.New("ENOSYS") }
	if got := r.Kernel(); got != "6.1.0-47-arm64" {
		t.Errorf("uname failing, /proc/sys/kernel/osrelease: %q", got)
	}
	r.Uname = func() (string, error) { return "  \n", nil }
	if got := r.Kernel(); got != "6.1.0-47-arm64" {
		t.Errorf("uname empty, /proc/sys/kernel/osrelease: %q", got)
	}
	if got := fakeHost(t, nil).Kernel(); got != "" {
		t.Errorf("neither: %q", got)
	}
}

func TestTheRealUnameReadsTheRunningKernel(t *testing.T) {
	release, err := uname()
	if err != nil {
		t.Fatal(err)
	}
	proc, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Skip("no /proc here")
	}
	if release == "" || release != strings.TrimSpace(string(proc)) {
		t.Fatalf("uname %q, /proc %q", release, proc)
	}
}

func TestOSReleaseParsing(t *testing.T) {
	text := `# a comment
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME='Debian GNU/Linux'
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
` + "QUOTED=\"a \\\"b\\\" \\\\ \\$c \\` d\"\n" + `not a line
lower_case=kept
 SPACED = no
EMPTY=
`
	want := map[string]string{
		"PRETTY_NAME":      "Debian GNU/Linux 12 (bookworm)",
		"NAME":             "Debian GNU/Linux",
		"VERSION_ID":       "12",
		"VERSION_CODENAME": "bookworm",
		"ID":               "debian",
		"HOME_URL":         "https://www.debian.org/",
		"QUOTED":           "a \"b\" \\ $c ` d",
		"lower_case":       "kept",
		"EMPTY":            "",
	}
	if got := ParseOSRelease(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestOSReleaseFromEtcElseUsrLibElseEmpty(t *testing.T) {
	both := fakeHost(t, map[string]string{"etc/os-release": "ID=etc\n", "usr/lib/os-release": "ID=usr\n"})
	if got := both.OSRelease()["ID"]; got != "etc" {
		t.Errorf("both: %q", got)
	}
	usr := fakeHost(t, map[string]string{"usr/lib/os-release": "ID=rocky\nVERSION_ID=\"9.6\"\n"})
	if got := usr.OSRelease(); !reflect.DeepEqual(got, map[string]string{"ID": "rocky", "VERSION_ID": "9.6"}) {
		t.Errorf("usr/lib: %#v", got)
	}
	if got := fakeHost(t, nil).OSRelease(); got == nil || len(got) != 0 {
		t.Errorf("neither: %#v", got)
	}
}

// Computed apart from this code, with Python's hmac: HMAC-SHA256(key = the machine id's 16 bytes,
// message = bytes.fromhex("852f4940356a4c1f9a7a461ded34e665")).
const (
	machineA = "0123456789abcdef0123456789abcdef"
	hostIDA  = "152e7ca814e49458c005837d88021375fa989e3e5fd6248d4f6f041961eaba24"
	machineB = "b08dfa6083e7567a1921a715000001fb"
	hostIDB  = "499bd67a36195d3160b80121c6c9baaa02b349f8db9df699f2aa8458f63365f4"
)

func TestHostIDFromEtcMachineID(t *testing.T) {
	r := fakeHost(t, map[string]string{"etc/machine-id": machineA + "\n", "var/lib/dbus/machine-id": machineB + "\n"})
	id, source, err := r.HostID()
	if err != nil || id != hostIDA || source != SourceMachineID {
		t.Fatalf("got %s %s %v", id, source, err)
	}
}

func TestHostIDFromDbusWhenEtcIsMissingEmptyOrInvalid(t *testing.T) {
	for name, etc := range map[string]*string{"missing": nil, "empty": ptr(""), "uninitialized": ptr("uninitialized\n"), "all zeros": ptr(strings.Repeat("0", 32)), "uppercase": ptr(strings.ToUpper(machineA))} {
		files := map[string]string{"var/lib/dbus/machine-id": machineB + "\n"}
		if etc != nil {
			files["etc/machine-id"] = *etc
		}
		id, source, err := fakeHost(t, files).HostID()
		if err != nil || id != hostIDB || source != SourceDbusMachineID {
			t.Errorf("%s: got %s %s %v", name, id, source, err)
		}
	}
}

func TestHostIDGeneratedOnceAndKept(t *testing.T) {
	r := fakeHost(t, map[string]string{"etc/machine-id": ""})
	first, source, err := r.HostID()
	if err != nil || source != SourceGenerated || len(first) != 64 {
		t.Fatalf("got %s %s %v", first, source, err)
	}
	keep := filepath.Join(r.StateDir, "host-id")
	info, err := os.Stat(keep)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("kept file: %v %v", info, err)
	}
	again, _, _ := r.HostID()
	if again != first {
		t.Fatalf("not stable: %s then %s", first, again)
	}
	// The kept id is a machine id like the others: derived the same way.
	raw, _ := os.ReadFile(keep)
	if m, ok := readMachineID(keep); !ok || derive(m) != first {
		t.Fatalf("kept %q doesn't derive %s", raw, first)
	}
}

func TestHostIDKeptFileInvalidIsRegenerated(t *testing.T) {
	r := fakeHost(t, map[string]string{"var/lib/flawrook/host-id": "garbage\n"})
	id, source, err := r.HostID()
	if err != nil || source != SourceGenerated || len(id) != 64 {
		t.Fatalf("got %s %s %v", id, source, err)
	}
	if _, ok := readMachineID(filepath.Join(r.StateDir, "host-id")); !ok {
		t.Fatal("the invalid file wasn't replaced")
	}
}

func TestHostIDGeneratedButNotKeptIsAnError(t *testing.T) {
	r := fakeHost(t, nil)
	r.StateDir = filepath.Join(r.Root, "blocker") // a file, so no directory can be made there
	if err := os.WriteFile(r.StateDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.HostID(); err == nil {
		t.Fatal("no error: an id that can't be kept would change on every run")
	}
}

func TestReadWithHostnameOverride(t *testing.T) {
	r := fakeHost(t, map[string]string{"etc/machine-id": machineA, "etc/os-release": "ID=alpine\n", "proc/sys/kernel/osrelease": "6.6.0\n"})
	real, err := r.Read("")
	if err != nil {
		t.Fatal(err)
	}
	want := Info{HostID: hostIDA, HostIDSource: SourceMachineID, Hostname: "real-host", Kernel: "6.6.0", OSRelease: map[string]string{"ID": "alpine"}}
	if !reflect.DeepEqual(real, want) {
		t.Fatalf("got %+v", real)
	}
	over, _ := r.Read("web-1")
	if over.Hostname != "web-1" || over.HostID != hostIDA {
		t.Fatalf("override: %+v", over)
	}
}

func ptr(s string) *string { return &s }
