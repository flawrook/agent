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

package main

import (
	"os"
	"strings"
	"testing"

	"flawrook.dev/agent/internal/sandbox"
)

// The agent's own path, stubbed: as root with the unit's marker, its first step refuses with exit 78 before it reads
// a config, lowers its priority or connects anywhere. So a run that gets that far is one the arguments let start.
func daemonStub(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the stub is the root-under-systemd refusal: run as root (scripts/docker-go.sh is)")
	}
	t.Setenv("FLAWROOK_SERVICE", "1")
}

// Nothing may follow the flags: a leftover argument gets the usage on stderr and exit 2, and the agent doesn't start.
// `version` is one of them: --version prints the version.
func TestALeftoverArgumentIsRefused(t *testing.T) {
	daemonStub(t)
	for _, tc := range []struct {
		args     []string
		leftover string // the first, which stderr names
	}{
		{[]string{"version"}, "version"},
		{[]string{"start"}, "start"},
		{[]string{"sbom-x", "image.tar"}, "sbom-x"},
		{[]string{"version", "--dry-run"}, "version"},
		{[]string{"--dry-run", "version"}, "version"},
		{[]string{"--interval", "20s", "extra"}, "extra"},
		{[]string{"--version", "extra"}, "extra"},
		{[]string{""}, ""},
	} {
		code, errs := runWith(t, tc.args...)
		want := "unexpected argument \"" + tc.leftover + "\"\nUsage: flawrook-agent [flags]\n"
		if code != 2 || !strings.HasPrefix(errs, want) || !strings.Contains(errs, "-version") || strings.Contains(errs, "msg=") {
			t.Errorf("%q: exit %d, stderr %q", tc.args, code, errs)
		}
	}
}

func TestTheFlagsAloneStillWork(t *testing.T) {
	daemonStub(t)
	// No arguments at all, the unit's ExecStart= and the image's entrypoint: the agent's own path.
	if code, errs := runWith(t); code != sandbox.ExitCode || !strings.Contains(errs, sandbox.Refusal) {
		t.Errorf("no arguments: exit %d, stderr %q", code, errs)
	}
	// The flags the tests and the docs start it with.
	for _, args := range [][]string{{"--dry-run"}, {"--interval", "20s"}, {"--config", "/etc/flawrook/agent.yaml"}} {
		if code, errs := runWith(t, args...); code != sandbox.ExitCode || !strings.Contains(errs, sandbox.Refusal) {
			t.Errorf("%q: exit %d, stderr %q", args, code, errs)
		}
	}
	// --version as before, its line on stdout.
	if code, errs := runWith(t, "--version"); code != 0 || errs != "" {
		t.Errorf("--version: exit %d, stderr %q", code, errs)
	}
	// An unknown flag as before.
	if code, errs := runWith(t, "--bogus"); code != 2 || !strings.HasPrefix(errs, "flag provided but not defined: -bogus\nUsage: flawrook-agent [flags]\n") {
		t.Errorf("--bogus: exit %d, stderr %q", code, errs)
	}
}

// sbom refuses a leftover itself, with its own line and exit 1, and writes nothing.
func TestTheSubcommandRefusesALeftover(t *testing.T) {
	daemonStub(t)
	p := archive(t)
	code, errs := runWith(t, "sbom", p, "extra")
	if code != 1 || errs != "flawrook-agent sbom: give one archive: flawrook-agent sbom [flags] <archive>\n" {
		t.Errorf("sbom %s extra: exit %d, stderr %q", p, code, errs)
	}
}
