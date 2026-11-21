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

// Package agent runs the hourly loop: build the inventory, send the full report when its hash changed
// since the server last acknowledged one, else a heartbeat. A SIGHUP rereads the config.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"flawrook.dev/agent/internal/client"
	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/hostinfo"
	"flawrook.dev/agent/internal/report"
)

// Retries after a 5xx, a timeout or no answer, each ±20%; then the agent waits for the next run.
var DefaultBackoff = []time.Duration{30 * time.Second, 2 * time.Minute, 8 * time.Minute}

// The longest a 429's Retry-After is honoured.
const maxRetryAfter = time.Hour

type Agent struct {
	Agent   report.Agent
	Load    func() (config.Config, error)
	Host    func(hostname string) (hostinfo.Info, error)
	Scan    func(ctx context.Context, cfg config.Config) ([]byte, error) // Syft's CycloneDX JSON
	Backoff []time.Duration
	Sleep   func(ctx context.Context, d time.Duration) error
	Log     *slog.Logger

	cfg     config.Config
	client  *client.Client
	acked   string // the last report hash the server acknowledged; memory only, so a restart sends a report
	pageURL string
}

// userAgent is "flawrook-agent/<version> (linux; <arch>)".
func (a *Agent) userAgent() string {
	return fmt.Sprintf("flawrook-agent/%s (%s; %s)", a.Agent.Version, a.Agent.OS, a.Agent.Arch)
}

// apply makes a config the current one; the client is rebuilt so a new proxy or CA applies.
func (a *Agent) apply(c config.Config) error {
	cl, err := client.New(c, a.userAgent())
	if err != nil {
		return err
	}
	a.cfg, a.client = c, cl
	return nil
}

// build scans and assembles one report.
func (a *Agent) build(ctx context.Context) (report.Report, error) {
	sbom, err := a.Scan(ctx, a.cfg)
	if err != nil {
		return report.Report{}, fmt.Errorf("inventory: %w", err)
	}
	host, err := a.Host(a.cfg.Hostname)
	if err != nil {
		return report.Report{}, err
	}
	return report.New(a.Agent, host, sbom)
}

// DryRun prints the exact report body, before gzip, and sends nothing.
func (a *Agent) DryRun(ctx context.Context, w io.Writer) error {
	c, err := a.Load()
	if err != nil {
		return err
	}
	a.cfg = c
	r, err := a.build(ctx)
	if err != nil {
		return err
	}
	body, err := r.JSON()
	if err != nil {
		return err
	}
	_, err = w.Write(append(body, '\n'))
	return err
}

// Cycle is one run: a heartbeat when nothing changed since the acknowledged report, else the report.
func (a *Agent) Cycle(ctx context.Context) error {
	defer debug.FreeOSMemory() // the scan's memory goes back between runs
	r, err := a.build(ctx)
	if err != nil {
		return err
	}
	// A heartbeat first, unless the inventory changed since the server last acknowledged one. With nothing
	// acknowledged yet (a start, a reload, a failed report) the server may well hold this inventory: a
	// fleet-wide restart then costs each host a heartbeat, and a 409 brings the report.
	if r.ReportHash == a.acked || a.acked == "" {
		body, err := json.Marshal(report.HeartbeatFor(r))
		if err != nil {
			return err
		}
		res, err := a.send(ctx, "heartbeat", func() (client.Result, error) { return a.client.Heartbeat(ctx, body) })
		if err != nil {
			return err
		}
		if res.Status >= 200 && res.Status < 300 {
			a.acked = r.ReportHash
		}
		if res.Status != http.StatusConflict {
			return a.outcome("heartbeat", res)
		}
		a.Log.Info("the server asks for the full report", "message", res.Message)
		a.acked = ""
	}
	body, err := r.JSON()
	if err != nil {
		return err
	}
	gz, err := report.Gzip(body)
	if err != nil {
		return err
	}
	res, err := a.send(ctx, "report", func() (client.Result, error) { return a.client.Report(ctx, gz) })
	if err != nil {
		return err
	}
	if res.Status >= 200 && res.Status < 300 {
		a.acked = r.ReportHash
		if res.URL != "" && res.URL != a.pageURL {
			a.pageURL = res.URL
			a.Log.Info("this host on FlawRook", "url", res.URL)
		}
		a.Log.Info("report sent", "status", res.Status, "bytes", len(gz), "reportHash", r.ReportHash)
		return nil
	}
	return a.outcome("report", res)
}

// send makes a request, retrying on no answer, a 5xx or a 429 (after its Retry-After) with the backoff;
// past the backoff the last answer or error stands.
func (a *Agent) send(ctx context.Context, what string, do func() (client.Result, error)) (client.Result, error) {
	for attempt := 0; ; attempt++ {
		res, err := do()
		retry := err != nil || res.Status >= 500 || res.Status == http.StatusTooManyRequests
		if !retry || attempt >= len(a.Backoff) {
			return res, err
		}
		wait := jitter(a.Backoff[attempt])
		if err == nil && res.Status == http.StatusTooManyRequests && res.RetryAfter > 0 {
			wait = min(res.RetryAfter, maxRetryAfter)
		}
		a.Log.Warn(what+" failed, retrying", "status", res.Status, "error", errString(err), "in", wait.Round(time.Second))
		if err := a.Sleep(ctx, wait); err != nil {
			return res, err
		}
	}
}

// outcome logs an answer that isn't a success; the next run tries again.
func (a *Agent) outcome(what string, res client.Result) error {
	switch {
	case res.Status >= 200 && res.Status < 300:
		a.Log.Info(what+" sent", "status", res.Status)
		return nil
	case res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden:
		return fmt.Errorf("%s: token rejected (%d, token %s): %s", what, res.Status, client.TokenHint(a.cfg.Token), res.Message)
	case res.Status >= 300 && res.Status < 400:
		return fmt.Errorf("%s: unexpected redirect to %s (%d), not followed: check the url", what, redirectHost(res.Location), res.Status)
	case res.Status == http.StatusUpgradeRequired:
		return fmt.Errorf("%s: upgrade the agent, the server no longer accepts protocol %d: %s", what, report.Protocol, res.Message)
	default:
		return fmt.Errorf("%s: %d %s", what, res.Status, res.Message)
	}
}

// Run loops until ctx ends: a first run after firstDelay, then one per interval. A SIGHUP rereads the
// config; when it changed, a run starts at once. Its heartbeat finds out whether the server (or the new
// token's project) holds this inventory; a hostname change, which changes the hash, sends the report.
func (a *Agent) Run(ctx context.Context, interval, firstDelay time.Duration) error {
	c, err := a.Load()
	if err != nil {
		return err
	}
	if err := a.apply(c); err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	a.Log.Info("started", "url", c.URL, "token", client.TokenHint(c.Token), "firstRunIn", firstDelay.Round(time.Second), "interval", interval)
	timer := time.NewTimer(firstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			c, err := a.Load()
			if err != nil {
				a.Log.Error("config not reloaded, the previous one stays", "error", err)
				continue
			}
			if c.Equal(a.cfg) {
				a.Log.Info("config reloaded, unchanged")
				continue
			}
			if err := a.apply(c); err != nil {
				a.Log.Error("config not reloaded, the previous one stays", "error", err)
				continue
			}
			a.Log.Info("config reloaded, running now", "url", c.URL, "token", client.TokenHint(c.Token))
			timer.Reset(0)
		case <-timer.C:
			if err := a.Cycle(ctx); err != nil && !errors.Is(err, context.Canceled) {
				a.Log.Error("run failed", "error", err)
			}
			timer.Reset(interval)
		}
	}
}

// FirstDelay spreads a fleet's first runs: up to a minute, never more than the interval.
func FirstDelay(interval time.Duration) time.Duration {
	return time.Duration(rand.Int64N(int64(min(time.Minute, interval)) + 1))
}

func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// SleepContext waits d, or until ctx ends.
func SleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redirectHost is where a redirect points, without its path or query: a URL can carry secrets.
func redirectHost(location string) string {
	u, err := url.Parse(location)
	if err != nil || u.Host == "" {
		return "the same host"
	}
	return u.Scheme + "://" + u.Host
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
