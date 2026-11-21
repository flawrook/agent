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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// reload is --reload, the unit's ExecReload=: SIGHUP to the running agent, a plain kill(2) inside the unit's
// sandbox, where systemd 235 to 238's system call filter stops a shell. It signals one process only: the
// unit's main process, which systemd passes both as the argument and as MAINPID, and only when that process
// is a flawrook-agent. procDir is /proc, and kill is syscall.Kill, but in tests.
func reload(arg string, getenv func(string) string, procDir string, kill func(int, syscall.Signal) error) error {
	// Above 1: kill(2) reads 0 as the process group and -1 as every process the user may signal.
	pid, err := strconv.Atoi(arg)
	if err != nil || pid <= 1 {
		return fmt.Errorf("--reload %q: not a process id", arg)
	}
	if mainPID, err := strconv.Atoi(getenv("MAINPID")); err != nil || mainPID != pid {
		return fmt.Errorf("--reload %d: not the unit's main process (MAINPID is %q); --reload is for the unit's ExecReload= only", pid, getenv("MAINPID"))
	}
	comm, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "comm"))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--reload %d: the agent isn't running (no process %d)", pid, pid)
	}
	if err != nil {
		return fmt.Errorf("--reload %d: %w", pid, err)
	}
	if name := strings.TrimSpace(string(comm)); name != "flawrook-agent" {
		return fmt.Errorf("--reload %d: process %d is %q, not flawrook-agent", pid, pid, name)
	}
	if err := kill(pid, syscall.SIGHUP); errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("--reload %d: the agent isn't running (no process %d)", pid, pid)
	} else if err != nil {
		return fmt.Errorf("--reload %d: %w", pid, err)
	}
	return nil
}
