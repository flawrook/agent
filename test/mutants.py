#!/usr/bin/env python3
# Copyright 2026 Binerals Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Mutation check for the agent's tests (the release gate's "mutants" step).

Each mutant breaks one behaviour the tests must catch: the file is changed, its package's tests run in
Docker (scripts/docker-go.sh), and the file is written back and checked by sha256, whatever happens.
One no-op control must survive. Every line the unit-file test asserts also gets a mutant that removes it.

    test/mutants.py              all mutants, from apps/agent
    test/mutants.py "nice 10"    only the named ones

Exit 0 when every behaviour mutant is killed by a test (not by a build error) and the control survives.
"""
import hashlib, os, re, subprocess, sys

A = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # apps/agent

M = [
 ("packaging/flawrook-agent.service", "ExecReload=/bin/sh -c 'kill -HUP $$MAINPID'", "ExecReload=/bin/kill -HUP $MAINPID", "./packaging/", "reload through /bin/kill"),
 ("internal/hostinfo/hostinfo.go", "mac := hmac.New(sha256.New, machineID[:])\n\tmac.Write(AppID[:])", "mac := hmac.New(sha256.New, AppID[:])\n\tmac.Write(machineID[:])", "./internal/hostinfo/", "HMAC key and message swapped"),
 ("internal/hostinfo/hostinfo.go", '{r.path("etc/machine-id"), SourceMachineID},\n\t\t{r.path("var/lib/dbus/machine-id"), SourceDbusMachineID},', '{r.path("var/lib/dbus/machine-id"), SourceDbusMachineID},\n\t\t{r.path("etc/machine-id"), SourceMachineID},', "./internal/hostinfo/", "dbus before /etc/machine-id"),
 ("internal/hostinfo/hostinfo.go", '|| text == strings.Repeat("0", 32)', '', "./internal/hostinfo/", "all-zero machine id accepted"),
 ("internal/hostinfo/hostinfo.go", 'if release, err := r.Uname(); err == nil && strings.TrimSpace(release) != "" {', 'if release, err := r.Uname(); false && err == nil && strings.TrimSpace(release) != "" {', "./internal/hostinfo/", "uname ignored"),
 ("internal/hostinfo/hostinfo.go", 'if raw, err := os.ReadFile(r.path("proc/sys/kernel/osrelease")); err == nil {', 'if raw, err := os.ReadFile(r.path("proc/sys/kernel/osrelease")); false && err == nil {', "./internal/hostinfo/", "no /proc fallback"),
 ("internal/config/config.go", "\t\tif v, ok := s.Flags[key]; ok {\n\t\t\treturn v\n\t\t}\n\t\tfor _, name := range envNames[key] {\n\t\t\tif v := s.Env(name); v != \"\" {\n\t\t\t\treturn v\n\t\t\t}\n\t\t}", "\t\tfor _, name := range envNames[key] {\n\t\t\tif v := s.Env(name); v != \"\" {\n\t\t\t\treturn v\n\t\t\t}\n\t\t}\n\t\tif v, ok := s.Flags[key]; ok {\n\t\t\treturn v\n\t\t}", "./internal/config/", "env over flags"),
 ("internal/config/config.go", "\t\treturn fromFile\n\t}", "\t\tif fromFile != \"\" {\n\t\t\treturn fromFile\n\t\t}\n\t\treturn fromFile\n\t}\n\t_ = 0", "./internal/config/", "noop control (must SURVIVE)"),
 ("internal/config/config.go", "\t\tif ip := net.ParseIP(host); host == \"localhost\" || (ip != nil && ip.IsLoopback()) {", "\t\tif ip := net.ParseIP(host); true || host == \"localhost\" || (ip != nil && ip.IsLoopback()) {", "./internal/config/", "plain http anywhere"),
 ("internal/report/report.go", '\tdelete(doc, "serialNumber")\n', '', "./internal/report/", "serial number hashed"),
 ("internal/report/report.go", '\t\t"kernel":       host.Kernel,\n', '', "./internal/report/", "kernel not hashed"),
 ("internal/report/report.go", "\t\tsort.Sort(byKey{t, keys})\n", "\t\tif false {\n\t\t\tsort.Sort(byKey{t, keys})\n\t\t}\n", "./internal/report/", "arrays not canonicalized"),
 ("internal/client/client.go", "\t\tif !pool.AppendCertsFromPEM(pem) {", "\t\tif pem = nil; !pool.AppendCertsFromPEM(pem) && false {", "./internal/client/", "CA bundle ignored"),
 ("internal/client/client.go", "\t\tProxy:               func(r *http.Request) (*url.URL, error) { return proxy(r.URL) },\n", "\t\tProxy:               func(r *http.Request) (*url.URL, error) { _ = proxy; return nil, nil },\n", "./internal/client/", "proxy ignored"),
 ("internal/client/client.go", "\treq.Header.Set(ProtocolKey, strconv.Itoa(report.Protocol))\n", "\t_ = strconv.Itoa(report.Protocol)\n", "./internal/client/", "no protocol header"),
 ("internal/agent/agent.go", "\tif r.ReportHash == a.acked || a.acked == \"\" {", "\tif false && (r.ReportHash == a.acked || a.acked == \"\") {", "./internal/agent/", "never a heartbeat"),
 ("internal/agent/agent.go", "\tif r.ReportHash == a.acked || a.acked == \"\" {", "\tif r.ReportHash == a.acked {", "./internal/agent/", "no heartbeat first after a start"),
 ("internal/agent/agent.go", "\t\tif res.Status >= 200 && res.Status < 300 {\n\t\t\ta.acked = r.ReportHash\n\t\t}\n", "", "./internal/agent/", "a heartbeat's 204 not acknowledged"),
 ("internal/agent/agent.go", "\t\tif res.Status != http.StatusConflict {\n\t\t\treturn a.outcome(\"heartbeat\", res)\n\t\t}", "\t\tif true {\n\t\t\treturn a.outcome(\"heartbeat\", res)\n\t\t}", "./internal/agent/", "409 doesn't send the report"),
 ("internal/agent/agent.go", "retry := err != nil || res.Status >= 500 || res.Status == http.StatusTooManyRequests", "retry := err != nil || res.Status >= 500", "./internal/agent/", "429 not retried"),
 ("internal/agent/agent.go", "\t\t\ttimer.Reset(0)\n", "", "./internal/agent/", "SIGHUP doesn't run at once"),
 ("internal/inventory/inventory.go", '\t"php-interpreter-cataloger",\n', '\t"php-interpreter-cataloger",\n\t"linux-kernel-cataloger",\n', "./internal/inventory/", "linux-kernel cataloger on"),
 ("internal/inventory/inventory.go", '"./var/lib/docker/**", ', '', "./internal/inventory/", "Docker storage walked"),
 ("internal/client/client.go", "\t\tCheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },\n", "", "./internal/client/ ./internal/agent/", "redirects followed"),
 ("internal/agent/agent.go", "\tcase res.Status >= 300 && res.Status < 400:\n\t\treturn fmt.Errorf(\"%s: unexpected redirect to %s (%d), not followed: check the url\", what, redirectHost(res.Location), res.Status)\n", "", "./internal/agent/", "3xx without its message"),
 ("internal/agent/agent.go", "\treturn u.Scheme + \"://\" + u.Host\n", "\treturn location\n", "./internal/agent/", "redirect logged with its query"),
 ("packaging/install.sh", "http://127.0.0.1 | http://127.0.0.1[:/]* |", "http://127.0.0.1* |", "./packaging/", "install.sh 127.0.0.1* (the review's bug)"),
 ("packaging/install.sh", " | \"http://[::1]\" | \"http://[::1]\"[:/]*) ;;", " | \"http://[::1]\"[:/]*) ;;", "./packaging/", "install.sh refuses http://[::1]"),
 ("internal/mounts/mounts.go", "\treturn networkTypes[fsType] || strings.HasPrefix(fsType, \"fuse.\")\n", "\treturn networkTypes[fsType]\n", "./internal/mounts/ ./internal/inventory/", "FUSE mounts walked"),
 ("internal/mounts/mounts.go", "\t\tif point != \"/\" && skippedType(m.Type) && !keep[point] {", "\t\tif point != \"/\" && skippedType(m.Type) {", "./internal/mounts/ ./internal/inventory/", "include_mounts ignored"),
 ("internal/mounts/mounts.go", "\t\tif point != \"/\" && skippedType(m.Type) && !keep[point] {", "\t\tif skippedType(m.Type) && !keep[point] {", "./internal/mounts/", "the root can be skipped"),
 ("internal/mounts/mounts.go", "\t\tout = append(out, Mount{Point: unescape(fields[4]), Type: rest[0]})", "\t\tout = append(out, Mount{Point: fields[4], Type: rest[0]})", "./internal/mounts/", "mountinfo escapes kept"),
 ("internal/mounts/mounts.go", "\t\tif strings.ContainsRune(`\\*?[]{}`, r) {", "\t\tif false && strings.ContainsRune(`\\*?[]{}`, r) {", "./internal/mounts/ ./internal/inventory/", "glob characters unescaped"),
 # 0.2.0: only what the catalogers read is walked (the review's memory finding).
 ("internal/inventory/narrow.go", "\treturn append(out, Heavy...)", "\treturn out", "./internal/inventory/", "application trees walked in allowed roots"),
 ("internal/inventory/narrow.go", "\t\t\t\treturn // all of dir is read", "\t\t\t\tcontinue", "./internal/inventory/", "an allowed directory narrowed again"),
 ("internal/inventory/narrow.go", "\t\t\tcase e.IsDir():", "\t\t\tcase e.IsDir() || e.Type()&os.ModeSymlink != 0:", "./internal/inventory/", "a symlink on the way followed"),
 ("internal/inventory/narrow.go", "\t\t\tcase !keep[e.Name()]:", "\t\t\tcase false && !keep[e.Name()]:", "./internal/inventory/", "nothing excluded"),
 ("internal/inventory/narrow.go", "\tallowed := append(append([]string(nil), Read...), include...)", "\tallowed := append([]string(nil), Read...)", "./internal/inventory/", "include_mounts narrowed away"),
 ("internal/inventory/narrow.go", "\t\tif r := resolved(root, a); r != \"\" {", "\t\tif r := resolved(root, a); false && r != \"\" {", "./internal/inventory/", "an allowed path through a symlink not resolved"),
 ("internal/inventory/narrow.go", "\t\tif err != nil || rel == \"..\" || strings.HasPrefix(rel, \"../\") {", "\t\tif err != nil {", "./internal/inventory/", "a symlink out of root resolved"),
 ("internal/inventory/narrow.go", "\t\"/usr/local/bin\", \"/usr/local/sbin\", \"/usr/local/lib\", \"/usr/local/go\",", "\t\"/usr/local/sbin\", \"/usr/local/lib\", \"/usr/local/go\",", "./internal/inventory/", "/usr/local/bin not read"),
 ("internal/inventory/inventory.go", "\tif secs < 10 {", "\tif secs < 0 {", "./internal/inventory/", "scan line: no tenths under 10 s"),
 # 0.2.0: read_protected, and the capability it stands for.
 ("internal/config/config.go", "\t\tc.ReadProtected = on\n", "\t\t_ = on\n", "./internal/config/", "read_protected's env and flag ignored"),
 ("internal/config/config.go", "\tc.ReadProtected = f.ReadProtected\n", "", "./internal/config/", "read_protected's file key ignored"),
 ("internal/config/config.go", "\t\t\treturn Config{}, fmt.Errorf(\"read_protected: %q is neither true nor false\", v)", "\t\t\ton, err = false, nil", "./internal/config/", "a bad read_protected read as off"),
 ("internal/sandbox/sandbox.go", "const capDACReadSearch = 1 << 2", "const capDACReadSearch = 1 << 1", "./internal/sandbox/", "CAP_DAC_OVERRIDE's bit"),
 ("internal/sandbox/sandbox.go", "\tcase uid == 0 || readProtected == readSearch:", "\tcase readProtected == readSearch:", "./internal/sandbox/", "root warned"),
 ("internal/sandbox/sandbox.go", "\tcase uid == 0 || readProtected == readSearch:", "\tcase uid == 0 || readProtected || readSearch:", "./internal/sandbox/", "a mismatch not warned"),
 ("internal/config/config.go", "\t} else if v := s.Env(\"FLAWROOK_INCLUDE_MOUNTS\"); v != \"\" {", "\t} else if v := s.Env(\"FLAWROOK_INCLUDE_MOUNTS\"); false && v != \"\" {", "./internal/config/", "include_mounts env ignored"),
 ("internal/config/config.go", "func (c Config) Equal(o Config) bool { return reflect.DeepEqual(c, o) }", "func (c Config) Equal(o Config) bool { _ = reflect.DeepEqual; return c.URL == o.URL && c.Token == o.Token }", "./internal/config/", "Equal blind to include_mounts"),
 ("internal/inventory/inventory.go", "Exclude: source.ExcludeConfig{Paths: append(append([]string(nil), Skip...), skip...)}", "Exclude: source.ExcludeConfig{Paths: append(append([]string(nil), Skip...), skip[:0]...)}", "./internal/inventory/", "mount exclusions not applied"),
 ("internal/priority/priority.go", "\tsetNice = func(tid int) error { return unix.Setpriority(unix.PRIO_PROCESS, tid, lowestNice) }", "\tsetNice = func(tid int) error { _ = unix.Setpriority; return nil }", "./internal/priority/", "nice never set"),
 ("internal/priority/priority.go", "\t\tif _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassBE<<ioprioClassShift|lowestIOLevel); errno != 0 {", "\t\tif _, _, errno := unix.Syscall(unix.SYS_GETPID, ioprioWhoProcess, uintptr(tid), ioprioClassBE<<ioprioClassShift|lowestIOLevel); errno != 0 {", "./internal/priority/", "IO priority never set"),
 ("internal/priority/priority.go", "\tentries, err := os.ReadDir(\"/proc/self/task\")\n\tif err != nil {", "\tentries, err := os.ReadDir(\"/proc/self/task\")\n\tif err != nil || true {", "./internal/priority/", "only the calling thread"),
 ("internal/priority/priority.go", "\tioprioClassBE    = 2  // IOPRIO_CLASS_BE, best-effort", "\tioprioClassBE    = 3  // IOPRIO_CLASS_BE, best-effort", "./internal/priority/", "the idle IO class"),
 ("internal/priority/priority.go", "\tlowestIOLevel    = 7", "\tlowestIOLevel    = 4", "./internal/priority/", "IO level 4"),
 ("internal/priority/priority.go", "\tlowestNice       = 19", "\tlowestNice       = 10", "./internal/priority/", "nice 10"),
]

# One mutant per line the unit-file test asserts: removing any one must fail it.
_test = open(os.path.join(A, "packaging/packaging_test.go")).read()
_block = _test[_test.index("func TestTheSystemdUnit"):_test.index("} {", _test.index("func TestTheSystemdUnit"))]
for _line in re.findall(r'^\t\t"(.+)",$', _block, re.M):
    _line = _line.replace('\\"', '"')
    M.append(("packaging/flawrook-agent.service", _line + "\n", "", "./packaging/", "unit without " + _line))

CONTROL = "noop control (must SURVIVE)"
only = sys.argv[1:]
killed = survived = build = 0
control_ok = None
for f, old, new, pkg, what in M:
    if only and what not in only:
        continue
    p = os.path.join(A, f)
    orig = open(p).read()
    h = hashlib.sha256(orig.encode()).hexdigest()
    if orig.count(old) != 1:
        sys.exit(f"mutant {what!r}: its text isn't in {f} exactly once; update the list")
    open(p, "w").write(orig.replace(old, new))
    try:
        r = subprocess.run(["scripts/docker-go.sh", "test", "-count=1", *pkg.split()], cwd=A, capture_output=True, text=True)
    finally:
        open(p, "w").write(orig)
        assert hashlib.sha256(open(p).read().encode()).hexdigest() == h, f"{f} not restored"
    died = r.returncode != 0
    by_build = "[build failed]" in r.stdout or "setup failed" in r.stdout
    if what == CONTROL:
        control_ok = not died
    elif died and not by_build:
        killed += 1
    elif died:
        build += 1
    else:
        survived += 1
    print(f"{'KILLED  ' if died else 'SURVIVED'} {what}{' (build error!)' if by_build else ''}", flush=True)

total = killed + survived + build
print(f"{killed} of {total} behaviour mutants killed by a test; {survived} survived; {build} killed only by a build error; "
      f"control {'survived' if control_ok else 'KILLED' if control_ok is False else 'not run'}")
sys.exit(0 if survived == 0 and build == 0 and control_ok is not False else 1)
