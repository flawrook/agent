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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// --reload signals the unit's main process, a flawrook-agent, and nothing else.
func TestReload(t *testing.T) {
	proc := t.TempDir()
	for pid, comm := range map[string]string{"4242": "flawrook-agent\n", "4343": "sshd\n"} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "comm"), []byte(comm), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, arg, mainPID string
		killErr            error
		want               string // "" for no error, else a part of it
		signalled          bool
	}{
		{"the unit's main process, an agent", "4242", "4242", nil, "", true},
		{"another pid than MAINPID", "4343", "4242", nil, "not the unit's main process", false},
		{"no MAINPID: not started by the unit", "4242", "", nil, "not the unit's main process", false},
		{"MAINPID is the pid, but not an agent", "4343", "4343", nil, `is "sshd", not flawrook-agent`, false},
		{"the process is gone", "4444", "4444", nil, "the agent isn't running (no process 4444)", false},
		{"gone between the check and the signal", "4242", "4242", syscall.ESRCH, "the agent isn't running (no process 4242)", true},
		{"refused", "4242", "4242", syscall.EPERM, "operation not permitted", true},
		{"-1, every process the user may signal", "-1", "-1", nil, "not a process id", false},
		{"0, the process group", "0", "0", nil, "not a process id", false},
		{"1, init", "1", "1", nil, "not a process id", false},
		{"empty", "", "", nil, "not a process id", false},
		{"not a number", "4242x", "4242x", nil, "not a process id", false},
	} {
		var signalled []int
		kill := func(pid int, sig syscall.Signal) error {
			if sig != syscall.SIGHUP {
				t.Errorf("%s: signal %v, want SIGHUP", c.name, sig)
			}
			signalled = append(signalled, pid)
			return c.killErr
		}
		err := reload(c.arg, func(k string) string {
			if k == "MAINPID" {
				return c.mainPID
			}
			return ""
		}, proc, kill)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got error %v, want one with %q", c.name, err, c.want)
		}
		if c.signalled != (len(signalled) == 1) || len(signalled) > 1 || c.signalled && signalled[0] != 4242 {
			t.Errorf("%s: signalled %v", c.name, signalled)
		}
	}
}

// The real thing: SIGHUP reaches this test process through kill(2).
func TestReloadSignalsTheProcess(t *testing.T) {
	proc := t.TempDir()
	pid := strconv.Itoa(os.Getpid())
	if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, pid, "comm"), []byte("flawrook-agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	if err := reload(pid, func(string) string { return pid }, proc, syscall.Kill); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hup:
	case <-time.After(5 * time.Second):
		t.Fatal("no SIGHUP within 5 s")
	}
}
