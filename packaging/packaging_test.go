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

package packaging

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/hostinfo"
	"flawrook.dev/agent/internal/sandbox"
)

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The unit's settings that the brief and the CTO set, line by line: every cap, priority and hardening
// line. The agent's first real run is on a production server, so losing any one of them fails here.
func TestTheSystemdUnit(t *testing.T) {
	unit := read(t, "flawrook-agent.service")
	lines := map[string]bool{}
	for _, l := range strings.Split(unit, "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	for _, want := range []string{
		"ExecStart=/usr/bin/flawrook-agent",
		// The agent signals itself: no shell (systemd 235 to 238's filter stops one), no /bin/kill (a minimal
		// Debian has no procps, and the reload failed there).
		"ExecReload=/usr/bin/flawrook-agent --reload $MAINPID",
		// Caps.
		"Environment=GOMEMLIMIT=96MiB",
		"MemoryMax=256M",
		// Priority: the lowest CPU priority, and the lowest IO priority that still makes progress.
		"Nice=19",
		"IOSchedulingClass=best-effort",
		"IOSchedulingPriority=7",
		// Its own user, no capabilities (0.2.0: read_protected's drop-in adds the one), its config through the group.
		"DynamicUser=yes",
		"CapabilityBoundingSet=",
		"NoNewPrivileges=yes",
		"SupplementaryGroups=flawrook",
		// Where a systemd before 232 ignored DynamicUser=: the agent knows its unit started it, refuses root,
		// and the refusal isn't restarted.
		"Environment=FLAWROOK_SERVICE=1",
		"RestartPreventExitStatus=78",
		// systemd 237 gives it no HOME, and Syft's home lookup runs getent, a process the filter stops.
		"Environment=HOME=/var/lib/flawrook",
		// Read-only but its state directory.
		"StateDirectory=flawrook",
		"StateDirectoryMode=0700",
		"UMask=0077",
		"ProtectSystem=strict",
		"ProtectHome=read-only",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"ProtectClock=yes",
		"ProtectHostname=yes",
		"ProtectProc=invisible",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		// @system-service, and for systemd 235 to 238, which doesn't know it, the sets and calls the agent makes.
		"SystemCallFilter=@system-service @basic-io @file-system @io-event @network-io @process @resources @signal getrandom ioctl madvise sched_getaffinity uname",
		// Outbound only.
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
		"SocketBindDeny=any",
	} {
		if !lines[want] {
			t.Errorf("the unit lacks %q", want)
		}
	}
	// The status the unit doesn't restart on is the agent's refusal of root.
	if want := "RestartPreventExitStatus=" + strconv.Itoa(sandbox.ExitCode); !lines[want] {
		t.Errorf("the unit lacks %q, the agent's exit status when it refuses root", want)
	}
	if strings.Contains(unit, "\nAmbientCapabilities=") || strings.Contains(unit, "CAP_DAC_READ_SEARCH\n") {
		t.Error("the unit grants a capability: it ships with none, and FLAWROOK_READ_PROTECTED=1's drop-in adds CAP_DAC_READ_SEARCH")
	}
	for _, never := range []string{"/bin/kill", "flra_", "FLAWROOK_TOKEN", "FLAWROOK_URL"} {
		if strings.Contains(unit, never) {
			t.Errorf("the unit has %q: no external kill, and the token and URL live in agent.yaml only", never)
		}
	}
	// The generated host id is kept where the unit's StateDirectory puts it.
	if got := hostinfo.New().StateDir; got != "/var/lib/flawrook" {
		t.Errorf("hostinfo keeps the generated id in %s, the unit's StateDirectory is /var/lib/flawrook", got)
	}
}

// The packages: agent.yaml is the admin's (kept on upgrade), readable by root and the flawrook group only, in a
// directory only they enter; the group exists before the files (preinstall).
func TestThePackagesConfig(t *testing.T) {
	nfpm := read(t, "nfpm.yaml")
	for _, want := range []string{
		"  - dst: /etc/flawrook\n    type: dir\n    file_info:\n      mode: 0750\n      group: flawrook",
		"    dst: /etc/flawrook/agent.yaml\n    type: config|noreplace\n    file_info:\n      mode: 0640\n      group: flawrook\n",
		"  preinstall: packaging/preinstall.sh\n",
		"    dst: /usr/lib/systemd/system/flawrook-agent.service\n",
	} {
		if !strings.Contains(nfpm, want) {
			t.Errorf("nfpm.yaml lacks:\n%s", want)
		}
	}
	if conf := read(t, "agent.yaml"); strings.Contains(conf, "\ntoken:") || strings.Contains(conf, "\nurl:") {
		t.Error("the packaged agent.yaml sets a key; it must only show them commented")
	}
}

// install.sh checks FLAWROOK_URL by the agent's rule, before anything else: https, or plain http only to
// localhost, 127.0.0.1 or [::1]. It never takes a URL the agent would refuse at start. The release URL
// is a dead port, so a URL that passes ends at the download and nothing is ever installed.
func TestInstallShURLRuleIsTheAgents(t *testing.T) {
	const refused = "FLAWROOK_URL must start with https://"
	for url, accepted := range map[string]bool{
		"https://flawrook.dev":         true,
		"https://10.0.0.5:8443/x":      true,
		"http://localhost":             true,
		"http://localhost:3003":        true,
		"http://localhost/":            true,
		"http://127.0.0.1":             true,
		"http://127.0.0.1:3003/api":    true,
		"http://[::1]":                 true,
		"http://[::1]:3003":            true,
		"http://127.0.0.1.example.com": false, // the review's case: the agent refuses it at start
		"http://127.0.0.1x":            false,
		"http://localhost.example.com": false,
		"http://localhostx":            false,
		"http://[::1].example.com":     false,
		"http://10.0.0.5":              false,
		"http://flawrook.dev":          false,
		"ftp://flawrook.dev":           false,
		"https://":                     false,
		"flawrook.dev":                 false,
	} {
		cmd := exec.Command("sh", "install.sh")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "FLAWROOK_URL=" + url, "FLAWROOK_RELEASE_URL=http://127.0.0.1:9"}
		out, _ := cmd.CombinedOutput()
		if got := !strings.Contains(string(out), refused); got != accepted {
			t.Errorf("install.sh %s: accepted %v, want %v (%s)", url, got, accepted, strings.TrimSpace(string(out)))
			continue
		}
		_, err := config.Load(config.Sources{Flags: map[string]string{"url": url}, Env: func(string) string { return "" }, Path: "/nonexistent/agent.yaml"})
		if accepted && err != nil {
			t.Errorf("install.sh takes %s, which the agent refuses: %v", url, err)
		}
	}
}
