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
A chart mutant runs test/chart-test.sh instead (KUBECONFORM=skip; HELM=helm, if set, passes through), and a signature
mutant the release gate's signature step alone, over dist/release from the gate's release step.
Each no-op control must survive. Every line the unit-file test asserts also gets a mutant that removes it.

    test/mutants.py              all mutants, from apps/agent
    test/mutants.py "nice 10"    only the named ones

Exit 0 when every behaviour mutant is killed by a test (not by a build error) and the controls survive.
"""
import hashlib, os, re, subprocess, sys

A = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # apps/agent

M = [
 ("packaging/flawrook-agent.service", "ExecReload=/usr/bin/flawrook-agent --reload $MAINPID", "ExecReload=/bin/sh -c 'kill -HUP $$MAINPID'", "./packaging/", "reload through a shell"),
 ("internal/hostinfo/hostinfo.go", "mac := hmac.New(sha256.New, id[:])\n\tmac.Write(app[:])", "mac := hmac.New(sha256.New, app[:])\n\tmac.Write(id[:])", "./internal/hostinfo/", "HMAC key and message swapped"),
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
 ("packaging/flawrook-agent.service", " sched_getaffinity uname\n", " sched_getaffinity\n", "./packaging/", "unit filter without uname (systemd 235 to 238)"),
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
 # 0.2.0: --reload, the unit's ExecReload= (no shell, which systemd 235 to 238's filter stops).
 ("cmd/flawrook-agent/reload.go", "\tif err != nil || pid <= 1 {", "\tif err != nil || pid < 0 {", "./cmd/flawrook-agent/", "--reload signals 0 or 1"),
 ("cmd/flawrook-agent/reload.go", "err != nil || mainPID != pid {", "false && (err != nil || mainPID != pid) {", "./cmd/flawrook-agent/", "--reload without the MAINPID check"),
 ("cmd/flawrook-agent/reload.go", "name != \"flawrook-agent\" {", "false && name != \"flawrook-agent\" {", "./cmd/flawrook-agent/", "--reload signals any program"),
 ("cmd/flawrook-agent/reload.go", "errors.Is(err, syscall.ESRCH) {", "false && errors.Is(err, syscall.ESRCH) {", "./cmd/flawrook-agent/", "--reload: a gone agent not said"),
# Cluster mode (M29 phase 2, cluster contract draft 2).
 ('internal/hostinfo/hostinfo.go', 'return appSpecific(key, ClusterAppID), nil', 'return appSpecific(key, AppID), nil', './internal/hostinfo/', 'cluster id under the host app id'),
 ('internal/kube/kube.go', 'Proxy:               nil, // never a proxy: see the package comment', 'Proxy:               http.ProxyFromEnvironment,', './internal/kube/', 'apiserver through HTTPS_PROXY'),
 ('internal/kube/kube.go', 'token, err := os.ReadFile(c.tokenFile)', 'token, err := []byte("first"), error(nil)', './internal/kube/', 'token never reread'),
 ('internal/kube/kube.go', 'if page.Metadata.Continue == "" {', 'if true {', './internal/kube/', 'first page only'),
 ('internal/kube/kube.go', 'if ev.Type != "BOOKMARK" {', 'if true {', './internal/kube/', 'bookmarks reach the handler'),
 ('internal/kube/kube.go', 'if status.Code == http.StatusGone {', 'if false {', './internal/kube/', "a 410 event isn't ErrGone"),
 ('internal/cluster/snapshot.go', 'if o.Controller == nil || !*o.Controller {', 'if o.Controller == nil {', './internal/cluster/', 'any owner counts, not the controller'),
 ('internal/cluster/snapshot.go', 'if h := p.Metadata.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {', 'if h := p.Metadata.Labels["pod-template-hash"]; h != "" {', './internal/cluster/', 'deployment without the suffix check'),
 ('internal/cluster/snapshot.go', 'cronJobSuffix = regexp.MustCompile(`^(.+)-\\d{8,}$`)', 'cronJobSuffix = regexp.MustCompile(`^(.+)-\\d{1,}$`)', './internal/cluster/', 'any numbered job is a cronjob'),
 ('internal/cluster/snapshot.go', 'return "StaticPod", strings.TrimSuffix(p.Metadata.Name, "-"+o.Name)', 'return "StaticPod", p.Metadata.Name', './internal/cluster/', 'static pod keeps its node suffix'),
 ('internal/cluster/snapshot.go', 'if !digestFormat.MatchString(id) {', 'if id == "" {', './internal/cluster/', 'any digest text accepted'),
 ('internal/cluster/snapshot.go', 'continue // still waiting: no image yet', '_ = 0', './internal/cluster/', 'waiting containers reported'),
 ('internal/cluster/snapshot.go', 'if a == "" || (b != "" && b < a) {', 'if a == "" || (b != "" && b > a) {', './internal/cluster/', 'largest ref wins'),
 ('internal/cluster/snapshot.go', 'case importName.MatchString(img.Repo):', 'case false:', './internal/cluster/', 'import names go to the registry'),
 ('internal/cluster/snapshot.go', 'case strings.HasPrefix(img.Platform, "windows/"):', 'case false:', './internal/cluster/', 'windows images go to the registry'),
 ('internal/cluster/snapshot.go', 'return !contains(s.Exclude, namespace)', 'return true', './internal/cluster/', 'exclude ignored'),
 ('internal/cluster/payload.go', 'f := nodeFacts{n.Kubelet, n.Runtime, n.OSImage, n.Kernel, n.OS, n.Arch, deref(n.Provider)}', 'f := nodeFacts{n.Name, n.Runtime, n.OSImage, n.Kernel, n.OS, n.Arch, deref(n.Provider)}', './internal/cluster/', 'node name in the hash'),
 ('internal/cluster/payload.go', 'c.Images = append(c.Images, image{img.Digest, img.Platform, img.Ref, img.Status.Status, img.Reason})', 'c.Images = append(c.Images, image{img.Digest, img.Platform, img.Ref, "", ""})', './internal/cluster/', 'status out of the hash'),
 ('internal/cluster/registry.go', 'preference = []string{"v7", "v6", "v5"}', 'preference = []string{"v6", "v7", "v5"}', './internal/cluster/', 'arm prefers v6'),
 ('internal/cluster/registry.go', 'preference = []string{"v8", ""}', 'preference = nil', './internal/cluster/', 'arm64 takes the first match'),
 ('internal/cluster/registry.go', 'if p.OS == goos && p.Architecture == arch {', 'if (p.OS == goos || true) && p.Architecture == arch {', './internal/cluster/', 'index match ignores the os'),
 ('internal/cluster/registry.go', 'case http.StatusNotFound:\n\t\t\treturn &Status{Status: NotPullable, Reason: "not-in-registry"', 'case 0:\n\t\t\treturn &Status{Status: NotPullable, Reason: "not-in-registry"', './internal/cluster/', "404 isn't not-in-registry"),
 ('internal/cluster/registry.go', 'case host == name.DefaultRegistry:', 'case false:', './internal/cluster/', 'no Docker Hub detail'),
 ('internal/cluster/registry.go', 'r.keychain = anonymous{}', 'r.keychain = authn.DefaultKeychain', './internal/cluster/', "a bad config file isn't anonymous"),
 ('internal/cluster/registry.go', 'case cfg.CredsStore != "" || len(cfg.CredHelpers) > 0:', 'case false:', './internal/cluster/', 'credential helpers used'),
 ('internal/cluster/registry.go', 'changed = r.keychain != nil && sum != r.configHash', 'changed = false', './internal/cluster/', 'config change not seen'),
 ('internal/cluster/registry.go', 'if err == nil || !unreachable(err) || attempt == 3 {', 'if err == nil || !unreachable(err) || attempt == 1 {', './internal/cluster/', 'unreachable after one try'),
 ('internal/cluster/registry.go', 'case r.credentials[host]:', 'case false:', './internal/cluster/', 'configured credential reads as none'),
 ('internal/cluster/runner.go', 'if why == OnChange && rep.ReportHash == r.acked {', 'if false {', './internal/cluster/', 'a change without a hash change runs'),
 ('internal/cluster/runner.go', 'if next := r.lastReport.Add(ReportPacing); r.Now().Before(next) {', 'if next := r.lastReport.Add(ReportPacing); false && r.Now().Before(next) {', './internal/cluster/', 'reports unpaced'),
 ('internal/cluster/runner.go', 'if st == nil && res.SizeBytes > r.Config.MaxImageBytes() {', 'if false {', './internal/cluster/', 'too-large images built'),
 ('internal/cluster/runner.go', 'return now.Add(time.Hour)\n\t\tcase 3:', 'return now.Add(6 * time.Hour)\n\t\tcase 3:', './internal/cluster/', 'second retry after 6 h'),
 ('internal/cluster/runner.go', 'if !ok {\n\t\tr.Log.Info("waiting for complete pod and node lists")', 'if !ok && false {\n\t\tr.Log.Info("waiting for complete pod and node lists")', './internal/cluster/', 'reports from incomplete lists'),
 ('internal/cluster/runner.go', 'if configChanged && s.status.Status == PrivateNoCredential {', 'if configChanged && false {', './internal/cluster/', "config change doesn't retry credentials"),
 ('internal/cluster/runner.go', 'if err != nil || res.Status != http.StatusConflict || attempt == 1 {', 'if true {', './internal/cluster/', 'needed 409 not followed by the report'),
 ('internal/cluster/runner.go', 'case ans.Status == http.StatusRequestEntityTooLarge:', 'case false:', './internal/cluster/', "upload 413 isn't too-large"),
 ('internal/cluster/runner.go', 'if rep.ReportHash == r.acked || r.acked == "" {', 'if rep.ReportHash == r.acked {', './internal/cluster/', 'no heartbeat first'),
 ('internal/cluster/runner.go', 'rep = fresh\n\t\t\tgz, err = gzipped(rep)', '_ = fresh', './internal/cluster/', 'a report retry resends the first body'),
 ('internal/cluster/runner.go', 'changed, err := r.buildNeeded(ctx, held, fresh)', 'changed, err := r.buildNeeded(ctx, held, rep)\n\t_ = fresh', './internal/cluster/', "the build round on the run's first snapshot"),
 ('internal/cluster/runner.go', 'if !listed[img.ImageKey] {', 'if false {', './internal/cluster/', "images the server's report doesn't list asked"),
 ('internal/cluster/runner.go', 'if err == nil && fresh.ReportHash != rep.ReportHash {', 'if false {', './internal/cluster/', 'a stale heartbeat retried'),
 ('internal/cluster/runner.go', 'st, why = r.upload(ctx, img, res, sbom)', 'st, _ = r.upload(ctx, img, res, sbom)', './internal/cluster/', "a refused upload's line without httpStatus and reason"),
 ('internal/cluster/builder.go', 'return n / 4 * 3', 'return n', './internal/cluster/', 'GOMEMLIMIT at the full limit'),
 ('internal/cluster/builder.go', 'high = max(high, n)', 'high = n', './internal/cluster/', 'memBuildMaxMiB is the last sample'),
 ('internal/cluster/sbom.go', 'WithAlias(source.Alias{Name: in.Name, Version: in.Key})', 'WithAlias(source.Alias{Name: in.Name, Version: "x"})', './internal/cluster/', 'sbom version not the manifest digest'),
 ('internal/cluster/sbom.go', 'WithDefaults("image")', 'WithDefaults("directory")', './internal/cluster/', "the cluster path's catalogers: directory, not image"),
 ('internal/cluster/archive.go', 'a := Archive{Tag: "docker-archive", KeyKind: "config",', 'a := Archive{Tag: "docker-archive", KeyKind: "manifest",', './internal/cluster/', 'a docker archive keyed by its manifest'),
 ('internal/cluster/archive.go', 'a := Archive{Tag: tag, Name: chosen.name, KeyKind: "manifest",', 'a := Archive{Tag: tag, Name: chosen.name, KeyKind: "config",', './internal/cluster/', 'an OCI image keyed by its config'),
 ('internal/cluster/archive.go', 'if a.SizeBytes > opt.MaxImageBytes {', 'if false {', './internal/cluster/', 'an archive over the image cap read'),
 ('internal/cluster/archive.go', 'if len(sbom) > maxArchiveSBOM {', 'if false {', './internal/cluster/', 'an SBOM over 20 MiB written'),
 ('internal/cluster/archive.go', 'if a.Several { // Syft', 'if false { // Syft', './internal/cluster/', "the platform not given to Syft"),
 ('internal/cluster/archive.go', 'if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" || (d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown") {', 'if false {', './internal/cluster/', 'attestation manifests counted as images'),
 ('internal/config/config.go', 'if err != nil || d < 10*time.Minute || d > 24*time.Hour {', 'if err != nil {', './internal/config/', 'interval unbounded'),
 ('internal/config/config.go', 'if c.SBOMConcurrency != 0 && (c.SBOMConcurrency < 1 || c.SBOMConcurrency > 4) {', 'if false {', './internal/config/', 'concurrency unbounded'),
 ('internal/config/config.go', 'DefaultSBOMMaxImageBytes = 300 << 20', 'DefaultSBOMMaxImageBytes = 1 << 30', './internal/config/', 'the 1 GiB default'),
 ('internal/client/client.go', 'return c.postLimit(ctx, ImagesNeededPath, body, false, neededLimit)', 'return c.post(ctx, ImagesNeededPath, body, false)', './internal/client/', 'images/needed answer cut at 64 KiB'),
 ('internal/client/client.go', 'return c.post(ctx, ClusterReportPath, gz, true)', 'return c.post(ctx, ClusterReportPath, gz, false)', './internal/client/', 'cluster report without gzip header'),
 # The Helm chart: its promises, held by test/chart-test.sh.
 ("deploy/helm/flawrook-agent/templates/clusterrole.yaml", "    verbs: [\"list\", \"watch\"]", "    verbs: [\"get\", \"list\", \"watch\"]", "chart", "chart: get on pods and nodes"),
 ("deploy/helm/flawrook-agent/templates/clusterrole.yaml", "    verbs: [\"get\"]", "    verbs: [\"get\", \"list\"]", "chart", "chart: namespaces listed"),
 ("deploy/helm/flawrook-agent/templates/clusterrole.yaml", "    resourceNames: [\"kube-system\"]\n", "", "chart", "chart: every namespace readable"),
 ("deploy/helm/flawrook-agent/templates/clusterrole.yaml", "    resources: [\"pods\", \"nodes\"]", "    resources: [\"pods\", \"nodes\", \"secrets\"]", "chart", "chart: the ClusterRole reads Secrets"),
 ("deploy/helm/flawrook-agent/templates/clusterrole.yaml", "{{- if .Values.rbac.create }}\n# Read-only", "{{- if true }}\n# Read-only", "chart", "chart: a ClusterRole despite rbac.create=false"),
 ("deploy/helm/flawrook-agent/values.yaml", "  readOnlyRootFilesystem: true", "  readOnlyRootFilesystem: false", "chart", "chart: a writable root"),
 ("deploy/helm/flawrook-agent/values.yaml", "  allowPrivilegeEscalation: false", "  allowPrivilegeEscalation: true", "chart", "chart: privilege escalation"),
 ("deploy/helm/flawrook-agent/values.yaml", "      - ALL", "      - NET_RAW", "chart", "chart: not every capability dropped"),
 ("deploy/helm/flawrook-agent/values.yaml", "    type: RuntimeDefault", "    type: Unconfined", "chart", "chart: no seccomp profile"),
 ("deploy/helm/flawrook-agent/values.yaml", "  runAsNonRoot: true", "  runAsNonRoot: false", "chart", "chart: root allowed"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "  replicas: 1", "  replicas: 2", "chart", "chart: two agents"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "              value: /scratch", "              value: /tmp", "chart", "chart: TMPDIR off the scratch volume"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "          emptyDir:\n            sizeLimit: {{ .Values.scratch.sizeLimit }}", "          emptyDir: {}", "chart", "chart: scratch uncapped"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "              mountPath: /etc/flawrook/registry\n              readOnly: true", "              mountPath: /etc/flawrook/registry", "chart", "chart: registry credentials mounted writable"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "              mountPath: /etc/flawrook/ca\n              readOnly: true", "              mountPath: /etc/flawrook/ca", "chart", "chart: the CA bundle mounted writable"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "(list \"kubernetes.default.svc\" \".svc\" \".cluster.local\" $.Values.proxy.noProxy)", "(list $.Values.proxy.noProxy)", "chart", "chart: the cluster's names not in NO_PROXY"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "                  key: {{ include \"flawrook-agent.tokenKey\" . }}", "                  key: token", "chart", "chart: existingSecretKey ignored"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "# One agent per cluster: a second would report the same cluster again.", "# One agent per cluster.", "chart", "noop control (must SURVIVE): chart"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "            - name: TMPDIR\n", "            - name: GOMEMLIMIT\n              value: 768MiB\n            - name: TMPDIR\n", "chart", "chart: GOMEMLIMIT set by the chart"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "              value: cluster\n", "              value: server\n", "chart", "chart: server mode"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "          terminationMessagePolicy: FallbackToLogsOnError\n", "", "chart", "chart: no log as the termination message"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "          terminationMessagePolicy: FallbackToLogsOnError\n", "          terminationMessagePolicy: FallbackToLogsOnError\n          livenessProbe:\n            exec:\n              command: [\"/usr/bin/flawrook-agent\", \"--version\"]\n", "chart", "chart: a probe"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "checksum/token: {{ .Values.flawrook.token | sha256sum }}", "checksum/token: \"0\"", "chart", "chart: a new token doesn't roll the pod"),
 ("deploy/helm/flawrook-agent/templates/deployment.yaml", "          emptyDir:\n            sizeLimit:", "          emptyDir:\n            medium: Memory\n            sizeLimit:", "chart", "chart: scratch in memory"),
 ("deploy/helm/flawrook-agent/values.yaml", "  url: https://flawrook.dev\n", "  url: \"\"\n", "chart", "chart: no default address"),
 ("deploy/helm/flawrook-agent/values.schema.json", "          \"minimum\": 1,\n          \"maximum\": 4\n", "          \"minimum\": 1\n", "chart", "chart: the schema takes 5 builds at once"),
 ("deploy/helm/flawrook-agent/templates/_helpers.tpl", "{{- if .Values.image.digest -}}", "{{- if false -}}", "chart", "chart: the digest ignored"),
 ("deploy/helm/flawrook-agent/templates/_helpers.tpl", "{{- .Values.flawrook.existingSecret | default (include \"flawrook-agent.fullname\" .) -}}", "{{- include \"flawrook-agent.fullname\" . -}}", "chart", "chart: existingSecret ignored"),
 ("deploy/helm/flawrook-agent/templates/secret.yaml", "{{- if not .Values.flawrook.existingSecret }}", "{{- if true }}", "chart", "chart: its own Secret beside existingSecret"),
 ("deploy/helm/flawrook-agent/values.schema.json", "  \"additionalProperties\": false,\n  \"required\": [\"flawrook\", \"image\", \"resources\", \"scratch\"],", "  \"required\": [\"flawrook\", \"image\", \"resources\", \"scratch\"],", "chart", "chart: the schema takes unknown keys"),
 ("deploy/helm/flawrook-agent/values.schema.json", "\"oneOf\": [", "\"x-oneOf\": [", "chart", "chart: the schema without its token rule"),
 ("deploy/helm/flawrook-agent/values.schema.json", "\"pattern\": \"^https://", "\"pattern\": \"^https?://", "chart", "chart: the schema takes plain http"),
 ("deploy/helm/flawrook-agent/values.schema.json", "\"required\": [\"memory\"],", "\"required\": [],", "chart", "chart: the schema takes no memory limit"),
 ("deploy/helm/flawrook-agent/values.yaml", "  maxImageBytes: 314572800\n", "  maxImageBytes: 1073741824\n", "chart", "chart: the 1 GiB default"),
 ("deploy/helm/flawrook-agent/presets/large-images.yaml", "scratch:\n  sizeLimit: 6Gi\n", "", "chart", "chart: the preset without its scratch size"),
 # The signing workflow's permissions, held by the release gate's signature step: id-token: write in any job.
 (".github/workflows/release-sign.yml", "      contents: write # the release's new asset\n", "      contents: write # the release's new asset\n      id-token: write\n", "signature", "signature: id-token in sign"),
 (".github/workflows/release-sign.yml", "      packages: write # the image and its signature on ghcr.io\n", "      packages: write # the image and its signature on ghcr.io\n      id-token: write\n", "signature", "signature: id-token in image"),
 (".github/workflows/release-sign.yml", "      packages: write # the chart and its signature on ghcr.io\n", "      packages: write # the chart and its signature on ghcr.io\n      id-token: write\n", "signature", "signature: id-token in chart"),
 (".github/workflows/release-sign.yml", "      contents: write # the edit that makes the release the latest\n", "      contents: write # the edit that makes the release the latest\n      id-token: write\n", "signature", "signature: id-token in latest"),
 (".github/workflows/release-sign.yml", "          cosign-release: v2.6.0 # its signatures verify with cosign 2 and 3 alike\n", "          cosign-release: v2.5.0 # its signatures verify with cosign 2 and 3 alike\n", "signature", "signature: two cosign versions"),
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
        if pkg == "chart":
            r = subprocess.run(["test/chart-test.sh", os.path.join(A, "dist", "chart-mutant")], cwd=A, capture_output=True, text=True,
                               env={**os.environ, "KUBECONFORM": "skip"})
        elif pkg == "signature":
            if not os.path.exists(os.path.join(A, "dist", "release", "install.sh")):
                sys.exit(f"mutant {what!r}: no dist/release/install.sh; run the release step first")
            env = {k: v for k, v in os.environ.items() if k != "GATE_HEALTH_URL"}  # no second health watch
            r = subprocess.run(["scripts/release-gate.sh", "mutant"], cwd=A, capture_output=True, text=True, env={**env, "GATE_STEPS": "signature"})
        else:
            r = subprocess.run(["scripts/docker-go.sh", "test", "-count=1", *pkg.split()], cwd=A, capture_output=True, text=True)
    finally:
        open(p, "w").write(orig)
        assert hashlib.sha256(open(p).read().encode()).hexdigest() == h, f"{f} not restored"
    died = r.returncode != 0
    by_build = "[build failed]" in r.stdout or "setup failed" in r.stdout
    if what.startswith(CONTROL):
        control_ok = control_ok is not False and not died
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
