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
package sandbox

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
