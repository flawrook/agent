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

package priority

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// nice reads a thread's nice value from /proc (field 19 of its stat, after the command's parentheses).
func nice(t *testing.T, tid int) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/task/" + strconv.Itoa(tid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+2:]))
	n, err := strconv.Atoi(fields[16]) // stat field 19; field 3 (state) is fields[0]
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ioprio(t *testing.T, tid int) int {
	t.Helper()
	r, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(tid), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	return int(r)
}

func taskIDs(t *testing.T) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, e := range entries {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, tid)
		}
	}
	return out
}

// Every thread of the process, the Go runtime's included: Linux keeps nice and IO priority per thread,
// and a thread made later inherits them from the one that makes it.
func TestLowerSetsEveryThreadToNice19AndIOBestEffort7(t *testing.T) {
	if errs := Lower(); len(errs) != 0 {
		t.Fatalf("refused: %v", errs)
	}
	want := 2<<13 | 7 // IOPRIO_CLASS_BE, level 7
	tids := taskIDs(t)
	if len(tids) < 2 {
		t.Fatalf("only %d threads: the test needs the runtime's own", len(tids))
	}
	for _, tid := range tids {
		if n := nice(t, tid); n != 19 {
			t.Errorf("thread %d: nice %d", tid, n)
		}
		if p := ioprio(t, tid); p != want {
			t.Errorf("thread %d: ioprio %#x, want %#x", tid, p, want)
		}
	}
	// Threads the runtime makes afterwards inherit both: 16 goroutines each pinned to an OS thread and kept
	// there make the runtime start new threads for the rest.
	before := map[int]bool{}
	for _, tid := range tids {
		before[tid] = true
	}
	release := make(chan struct{})
	defer close(release)
	seen := make(chan int)
	for i := 0; i < 16; i++ {
		go func() {
			runtime.LockOSThread()
			seen <- unix.Gettid()
			<-release
		}()
	}
	fresh := 0
	for i := 0; i < 16; i++ {
		tid := <-seen
		if !before[tid] {
			fresh++
		}
		if n, p := nice(t, tid), ioprio(t, tid); n != 19 || p != want {
			t.Errorf("thread %d: nice %d, ioprio %#x", tid, n, p)
		}
	}
	if fresh == 0 {
		t.Fatal("no thread made after Lower: the inheritance went untested")
	}
}

// Refused (a seccomp filter, an old kernel): Lower reports it and the agent runs on at normal priority.
func TestARefusalIsReportedNotFatal(t *testing.T) {
	realNice, realIO := setNice, setIO
	defer func() { setNice, setIO = realNice, realIO }()
	setNice = func(int) error { return syscall.EPERM }
	setIO = func(int) error { return syscall.ENOSYS }
	errs := Lower()
	if len(errs) != 2 || !errors.Is(errs[0], syscall.EPERM) || !errors.Is(errs[1], syscall.ENOSYS) {
		t.Fatalf("got %v", errs)
	}
}
