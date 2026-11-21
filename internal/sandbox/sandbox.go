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

// Package sandbox stops the agent when systemd starts it as root. Its unit runs it as a user of its own
// (DynamicUser=), which systemd before 232 ignores without an error: the agent would run as root, and nobody
// would know. install.sh and the packages refuse such a systemd; this covers a unit enabled by hand all the same.
// It also checks read_protected against the capability the agent holds.
package sandbox

import (
	"strconv"
	"strings"
)

// ExitCode is the refusal's exit status, EX_CONFIG in sysexits.h. The unit's RestartPreventExitStatus= names it,
// so systemd doesn't restart the agent into the same refusal every minute.
const ExitCode = 78

// Refusal is the line the agent logs before it exits with ExitCode.
const Refusal = "running as root under systemd: this systemd ignored DynamicUser=. Use systemd 235 or newer, or run the agent as a non-root user without systemd. Not started."

// RootUnderSystemd tells whether the agent runs as root under systemd: uid 0, started by its own unit, whose
// Environment= sets FLAWROOK_SERVICE in every systemd version, or by any unit of systemd 232 and later, which
// sets INVOCATION_ID. Without either, as a plain binary, it runs as any user.
func RootUnderSystemd(uid int, getenv func(string) string) bool {
	return uid == 0 && (getenv("FLAWROOK_SERVICE") != "" || getenv("INVOCATION_ID") != "")
}

// capDACReadSearch is CAP_DAC_READ_SEARCH's bit in the capability masks of /proc/self/status.
const capDACReadSearch = 1 << 2

// ReadSearch tells whether the effective capabilities in status, the text of /proc/self/status, hold
// CAP_DAC_READ_SEARCH.
func ReadSearch(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if mask, ok := strings.CutPrefix(line, "CapEff:"); ok {
			v, err := strconv.ParseUint(strings.TrimSpace(mask), 16, 64)
			return err == nil && v&capDACReadSearch != 0
		}
	}
	return false
}

// ReadProtectedMismatch is the warning when read_protected and the capability disagree, or "" when they agree.
// The capability comes only from the unit's drop-in (install.sh's FLAWROOK_READ_PROTECTED=1), so either way the
// fix is install.sh's. Root reads every file whatever the setting, and gets no warning.
func ReadProtectedMismatch(readProtected bool, uid int, readSearch bool) string {
	switch {
	case uid == 0 || readProtected == readSearch:
		return ""
	case readProtected:
		return "read_protected is on, but the agent lacks CAP_DAC_READ_SEARCH and reads world-readable files only: run install.sh with FLAWROOK_READ_PROTECTED=1, or set read_protected: false"
	default:
		return "the agent holds CAP_DAC_READ_SEARCH, but read_protected is off: run install.sh with FLAWROOK_READ_PROTECTED=0 to take it away, or set read_protected: true"
	}
}
