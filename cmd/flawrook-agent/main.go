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

// flawrook-agent reports a server's OS packages and runtimes to FlawRook every hour: outbound HTTPS
// only, no port opened, no remote commands, read-only everywhere but its own state directory.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"flawrook.dev/agent/internal/agent"
	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/hostinfo"
	"flawrook.dev/agent/internal/inventory"
	"flawrook.dev/agent/internal/mounts"
	"flawrook.dev/agent/internal/priority"
	"flawrook.dev/agent/internal/report"
	"flawrook.dev/agent/internal/sandbox"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "0.0.0-dev"

// The default soft memory limit when GOMEMLIMIT isn't set; the systemd unit caps the process at 256M.
const memoryLimit = 96 << 20

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("flawrook-agent", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "the config file")
	fs.String("url", "", "FlawRook's address (env FLAWROOK_URL, default "+config.DefaultURL+")")
	fs.String("token", "", "the agent token (env FLAWROOK_TOKEN; prefer the config file, a flag shows in ps)")
	fs.String("hostname", "", "the hostname to report instead of the real one (env FLAWROOK_HOSTNAME)")
	fs.String("ca-file", "", "a PEM bundle to trust besides the system's (env FLAWROOK_CA_FILE)")
	fs.String("https-proxy", "", "the proxy for HTTPS (env HTTPS_PROXY)")
	fs.String("no-proxy", "", "hosts to reach without the proxy (env NO_PROXY)")
	fs.String("include-mounts", "", "network or FUSE mount points to walk all the same, comma-separated (env FLAWROOK_INCLUDE_MOUNTS)")
	fs.Bool("read-protected", false, "the unit gives the agent CAP_DAC_READ_SEARCH, to read files no other user may (env FLAWROOK_READ_PROTECTED; install.sh sets it)")
	dryRun := fs.Bool("dry-run", false, "print the exact report, before gzip, and send nothing")
	interval := fs.Duration("interval", time.Hour, "for testing only: the time between runs")
	showVersion := fs.Bool("version", false, "print the version")
	reloadPID := fs.String("reload", "", "for the unit's ExecReload= only: send SIGHUP to the running agent, $MAINPID")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("flawrook-agent %s (protocol %d, %s)\n", version, report.Protocol, runtime.Version())
		return 0
	}
	// --reload does that and nothing else, whatever its value: an empty one is refused, not an agent started.
	reloading := false
	fs.Visit(func(f *flag.Flag) { reloading = reloading || f.Name == "reload" })
	if reloading {
		if err := reload(*reloadPID, os.Getenv, "/proc", syscall.Kill); err != nil {
			fmt.Fprintln(os.Stderr, "flawrook-agent:", err)
			return 1
		}
		return 0
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Root under systemd means a systemd that ignored the unit's DynamicUser=: refused before anything else,
	// --dry-run included, with the exit status the unit doesn't restart on. --version above answers anyone.
	if sandbox.RootUnderSystemd(os.Geteuid(), os.Getenv) {
		log.Error(sandbox.Refusal)
		return sandbox.ExitCode
	}
	// The flags given, by the config's keys ("ca-file" is ca_file).
	flags := map[string]string{}
	fs.Visit(func(f *flag.Flag) {
		if key := strings.ReplaceAll(f.Name, "-", "_"); key != "config" && key != "dry_run" && key != "interval" && key != "version" {
			flags[key] = f.Value.String()
		}
	})
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memoryLimit)
	}
	// Gentle however it is started: the unit sets the same, and a manual run gets it here. Refused, the
	// agent runs on at normal priority and says so.
	for _, err := range priority.Lower() {
		log.Warn("priority not lowered, running at normal priority", "error", err)
	}
	host := hostinfo.New()
	skippedMounts := "" // logged when it changes
	readProtectedWarning := ""
	a := &agent.Agent{
		Agent: report.Agent{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH},
		Load: func() (config.Config, error) {
			c, err := config.Load(config.Sources{Flags: flags, Env: os.Getenv, Path: *path})
			if err == nil { // at the start and on each reload: read_protected against the capability held
				status, _ := os.ReadFile("/proc/self/status")
				if w := sandbox.ReadProtectedMismatch(c.ReadProtected, os.Geteuid(), sandbox.ReadSearch(string(status))); w != readProtectedWarning {
					if readProtectedWarning = w; w != "" {
						log.Warn(w)
					}
				}
			}
			return c, err
		},
		Host:    host.Read,
		Backoff: agent.DefaultBackoff,
		Sleep:   agent.SleepContext,
		Log:     log,
		Scan: func(ctx context.Context, cfg config.Config) ([]byte, error) {
			skip := mounts.Skipped(mounts.Read(), cfg.IncludeMounts)
			if list := strings.Join(skip, " "); list != skippedMounts {
				skippedMounts = list
				log.Info("network and FUSE mounts not walked (include_mounts walks one)", "mounts", list)
			}
			// Only what the catalogers read is walked (inventory.Narrow), less the skipped mounts.
			sbom, stats, err := inventory.Build(ctx, "/", version, append(mounts.Patterns(skip), inventory.Narrow("/", cfg.IncludeMounts)...))
			if err == nil {
				log.Info(stats.Line(), "packages", stats.Packages, "ms", stats.Elapsed.Milliseconds(), "maxRssKiB", stats.MaxRSSKiB)
			}
			return sbom, err
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *dryRun {
		if err := a.DryRun(ctx, os.Stdout); err != nil {
			log.Error("dry run failed", "error", err)
			return 1
		}
		return 0
	}
	if err := a.Run(ctx, *interval, agent.FirstDelay(*interval)); err != nil {
		log.Error("not started", "error", err)
		return 1
	}
	return 0
}
