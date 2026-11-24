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

//go:build linux

// Package priority lowers the agent's own CPU and IO priority before it scans, so that a run outside
// systemd (by hand, from cron, in a container) is as gentle as the service, whose unit sets the same:
// Nice=19, and best-effort IO at level 7 (not the idle class, which starves on a disk that is never idle).
package priority

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	ioprioWhoProcess = 1  // IOPRIO_WHO_PROCESS: one thread, by its id
	ioprioClassBE    = 2  // IOPRIO_CLASS_BE, best-effort
	ioprioClassShift = 13 // IOPRIO_CLASS_SHIFT
	lowestIOLevel    = 7
	lowestNice       = 19
)

// The two calls, replaceable in tests. Raising one's own nice value and lowering one's own IO priority
// need no privilege; a seccomp filter or an old kernel can still refuse them.
var (
	setNice = func(tid int) error { return unix.Setpriority(unix.PRIO_PROCESS, tid, lowestNice) }
	setIO   = func(tid int) error {
		if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassBE<<ioprioClassShift|lowestIOLevel); errno != 0 {
			return errno
		}
		return nil
	}
)

// Lower sets every thread of this process to nice 19 and best-effort IO level 7. Linux keeps both per
// thread, and a thread made later inherits them from the one that makes it, so the Go runtime's threads
// all follow. It returns the refusals, at most one per kind; the agent then runs on at normal priority.
func Lower() []error {
	var niceErr, ioErr error
	for _, tid := range threads() {
		if err := setNice(tid); err != nil && niceErr == nil && !errors.Is(err, unix.ESRCH) { // ESRCH: the thread ended meanwhile
			niceErr = fmt.Errorf("nice %d: %w", lowestNice, err)
		}
		if err := setIO(tid); err != nil && ioErr == nil && !errors.Is(err, unix.ESRCH) {
			ioErr = fmt.Errorf("IO priority best-effort %d: %w", lowestIOLevel, err)
		}
	}
	var errs []error
	for _, err := range []error{niceErr, ioErr} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// threads are this process's thread ids; just the calling thread's when /proc can't be read.
func threads() []int {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return []int{unix.Gettid()}
	}
	var out []int
	for _, e := range entries {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, tid)
		}
	}
	return out
}
