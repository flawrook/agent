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

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"flawrook.dev/agent/internal/client"
	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/hostinfo"
	"flawrook.dev/agent/internal/kube"
	"flawrook.dev/agent/internal/report"
)

// The contract's pacing: a change runs after a minute of quiet, and reports come at most every 5 minutes.
const (
	Quiet        = time.Minute
	ReportPacing = 5 * time.Minute
	BuildTimeout = 10 * time.Minute
	// The API's body limit, inflated: an SBOM over it is too-large / sbom, not sent.
	MaxSBOMBytes = 20 << 20
)

// Images resolves and builds image SBOMs; *Builder in production.
type Images interface {
	Round() (configChanged bool, warning string)
	Resolve(ctx context.Context, img Image) (Resolved, *Status)
	Build(ctx context.Context, img Image, res Resolved) (sbom []byte, packages int, st *Status)
}

// Runner is cluster mode's loop.
type Runner struct {
	Agent   Agent
	Config  config.Config
	Client  *client.Client
	Source  Source
	Images  Images
	Backoff []time.Duration
	Sleep   func(ctx context.Context, d time.Duration) error
	Now     func() time.Time
	Log     *slog.Logger
	Memory  func() func() []any // started as a build starts; stopping it gives the built line's memory fields

	info       Info
	acked      string
	pageURL    string
	lastReport time.Time
	mu         sync.Mutex
	images     map[ImageKey]*imageState
}

// imageState is what the agent knows of an image it couldn't build, and when to try again.
type imageState struct {
	status   Status
	attempts int
	retryAt  time.Time // zero: never, until the agent restarts or (for credentials) the registry config changes
}

// Identify reads kube-system's UID (the cluster id) and the cluster's version. An agent that can't read kube-system
// sends nothing: the caller exits, which shows as a CrashLoopBackOff.
func (r *Runner) Identify(uid string, version *string) error {
	id, err := hostinfo.ClusterID(uid)
	if err != nil {
		return err
	}
	r.info = Info{ID: id, Version: version, Scope: Scope{Include: r.Config.NamespacesInclude, Exclude: r.Config.NamespacesExclude}}
	if r.Config.ClusterName != "" {
		name := r.Config.ClusterName
		r.info.Name = &name
	}
	return nil
}

func (r *Runner) scope() Scope { return r.info.Scope }

// errWaiting ends a run whose new snapshot came from incomplete lists: it sends nothing more.
var errWaiting = errors.New("waiting for complete pod and node lists")

// errStale ends a heartbeat's retries when the cluster changed during them: the report goes instead.
var errStale = errors.New("the cluster changed during the retries")

// current is a new snapshot, for the run's start, a retry or the build round; errWaiting while the lists aren't
// complete.
func (r *Runner) current() (Report, error) {
	rep, ok := r.snapshot()
	if !ok {
		r.Log.Info("waiting for complete pod and node lists")
		return Report{}, errWaiting
	}
	return rep, nil
}

// snapshot builds the report from the source; ok is false while the lists aren't complete.
func (r *Runner) snapshot() (Report, bool) {
	pods, nodes, complete := r.Source.State()
	if !complete {
		return Report{}, false
	}
	r.mu.Lock()
	statuses := map[ImageKey]Status{}
	for k, s := range r.images {
		statuses[k] = s.status
	}
	r.mu.Unlock()
	snap := Build(pods, nodes, r.scope(), statuses)
	r.prune(snap)
	return NewReport(r.Agent, r.info, snap), true
}

// prune forgets images no longer running.
func (r *Runner) prune(snap Snapshot) {
	running := map[ImageKey]bool{}
	for _, img := range snap.Images {
		running[img.ImageKey] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.images {
		if !running[k] {
			delete(r.images, k)
		}
	}
}

// Trigger is why a cycle runs.
type Trigger int

const (
	OnInterval Trigger = iota // sends a heartbeat when nothing changed
	OnChange                  // runs only when the controller-level snapshot changed since the acknowledged report
)

// Cycle is one run: heartbeat or report, then the images the workspace needs. It returns when a report it wants to
// send must wait for the pacing, so the caller can run again at that time.
func (r *Runner) Cycle(ctx context.Context, why Trigger) (retryAt time.Time, err error) {
	defer debug.FreeOSMemory()
	defer func() {
		if errors.Is(err, errWaiting) { // logged where it was seen; the run just ends
			err = nil
		}
	}()
	rep, err := r.current()
	if err != nil {
		return time.Time{}, err
	}
	if why == OnChange && rep.ReportHash == r.acked {
		return time.Time{}, nil
	}
	held, at, err := r.sync(ctx, rep)
	if err != nil || !at.IsZero() {
		return at, err
	}
	// The build round works from what runs now, not from what ran before the sync's retries.
	fresh, err := r.current()
	if err != nil {
		return time.Time{}, err
	}
	changed, err := r.buildNeeded(ctx, held, fresh)
	if err != nil {
		return time.Time{}, err
	}
	if changed { // a status changed during the round: the report says so
		if rep, ok := r.snapshot(); ok && rep.ReportHash != r.acked {
			_, at, err := r.send(ctx, rep)
			return at, err
		}
	}
	return time.Time{}, nil
}

// sync brings the server to this report: a heartbeat when the hash is the acknowledged one (or nothing is acknowledged
// yet), else the report. It answers the report the server holds.
func (r *Runner) sync(ctx context.Context, rep Report) (Report, time.Time, error) {
	if rep.ReportHash == r.acked || r.acked == "" {
		body, err := json.Marshal(HeartbeatFor(rep))
		if err != nil {
			return Report{}, time.Time{}, err
		}
		// Each retry looks again first: once the cluster has changed, the heartbeat's hash is stale.
		res, err := r.retrying(ctx, "heartbeat", func() error {
			fresh, err := r.current()
			if err == nil && fresh.ReportHash != rep.ReportHash {
				rep, err = fresh, errStale
			}
			return err
		}, func() (client.Result, error) { return r.Client.ClusterHeartbeat(ctx, body) })
		if errors.Is(err, errStale) {
			return r.send(ctx, rep)
		}
		if err != nil {
			return Report{}, time.Time{}, err
		}
		if res.Status >= 200 && res.Status < 300 {
			r.acked = rep.ReportHash
			return rep, time.Time{}, nil
		}
		if res.Status != http.StatusConflict {
			return Report{}, time.Time{}, r.outcome("heartbeat", res)
		}
		r.Log.Info("the server asks for the full report", "message", res.Message)
		r.acked = ""
	}
	return r.send(ctx, rep)
}

// send sends the report, or says when the pacing allows it. Each retry sends a new snapshot, never one the cluster
// has moved on from. It answers the report the server acknowledged.
func (r *Runner) send(ctx context.Context, rep Report) (Report, time.Time, error) {
	if !r.lastReport.IsZero() {
		if next := r.lastReport.Add(ReportPacing); r.Now().Before(next) {
			return Report{}, next, nil
		}
	}
	gz, err := gzipped(rep)
	if err != nil {
		return Report{}, time.Time{}, err
	}
	res, err := r.retrying(ctx, "report", func() error {
		fresh, err := r.current()
		if err == nil {
			rep = fresh
			gz, err = gzipped(rep)
		}
		return err
	}, func() (client.Result, error) { return r.Client.ClusterReport(ctx, gz) })
	if err != nil {
		return Report{}, time.Time{}, err
	}
	if res.Status < 200 || res.Status >= 300 {
		return Report{}, time.Time{}, r.outcome("report", res)
	}
	r.acked, r.lastReport = rep.ReportHash, r.Now()
	if res.URL != "" && res.URL != r.pageURL {
		r.pageURL = res.URL
		r.Log.Info("this cluster on FlawRook", "url", res.URL)
	}
	r.Log.Info("report sent", "status", res.Status, "bytes", len(gz), "workloads", len(rep.Workloads), "images", len(rep.Images), "reportHash", rep.ReportHash)
	return rep, time.Time{}, nil
}

func gzipped(rep Report) ([]byte, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	return report.Gzip(body)
}

// buildNeeded asks which scannable images the workspace needs, then builds and uploads them. It asks only about the
// images both the report the server holds and the fresh snapshot list: an image that stopped running isn't built,
// and one the server's report doesn't list yet waits for the next report (its upload would get a 409). It answers
// whether any image's status changed.
func (r *Runner) buildNeeded(ctx context.Context, held, fresh Report) (bool, error) {
	configChanged, warning := r.Images.Round()
	if warning != "" {
		r.Log.Warn(warning)
	}
	var byKey map[ImageKey]Image
	var ask []ImageKey
	var res client.Result
	var err error
	for attempt := 0; ; attempt++ {
		byKey, ask = r.toAsk(held, fresh, configChanged)
		if len(ask) == 0 {
			return false, nil
		}
		var body []byte
		if body, err = json.Marshal(Needed{Protocol: report.Protocol, Agent: r.Agent, Cluster: ID{r.info.ID}, Images: ask}); err != nil {
			return false, err
		}
		res, err = r.retrying(ctx, "images/needed", nil, func() (client.Result, error) { return r.Client.ImagesNeeded(ctx, body) })
		if err != nil || res.Status != http.StatusConflict || attempt == 1 {
			break
		}
		// The server has no entry for the cluster: the fresh snapshot's report, then the question again.
		r.Log.Info("the server asks for the full report", "message", res.Message)
		r.acked = ""
		var at time.Time
		if held, at, err = r.send(ctx, fresh); err != nil || !at.IsZero() {
			return false, err
		}
	}
	if err != nil {
		return false, err
	}
	if res.Status != http.StatusOK {
		return false, r.outcome("images/needed", res)
	}
	var answer NeededAnswer
	if err := json.Unmarshal(res.Body, &answer); err != nil {
		return false, fmt.Errorf("images/needed: %w", err)
	}
	var queue []Image
	for _, k := range answer.Needed {
		if img, ok := byKey[k]; ok {
			queue = append(queue, img)
		}
	}
	// Images the server holds again (another cluster built them) lose their status.
	changed := false
	r.mu.Lock()
	needed := map[ImageKey]bool{}
	for _, img := range queue {
		needed[img.ImageKey] = true
	}
	for _, k := range ask {
		if s := r.images[k]; s != nil && !needed[k] {
			delete(r.images, k)
			changed = true
		}
	}
	r.mu.Unlock()

	sem := make(chan struct{}, r.Config.Concurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, img := range queue {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(img Image) {
			defer func() { <-sem; wg.Done() }()
			if r.buildOne(ctx, img) {
				mu.Lock()
				changed = true
				mu.Unlock()
			}
		}(img)
	}
	wg.Wait()
	return changed, nil
}

// toAsk is the images to ask about: those both reports list that need no request to be known, less the ones held
// until a later try.
func (r *Runner) toAsk(held, fresh Report, configChanged bool) (map[ImageKey]Image, []ImageKey) {
	listed := map[ImageKey]bool{}
	for _, img := range held.Images {
		listed[img.ImageKey] = true
	}
	now := r.Now()
	byKey := map[ImageKey]Image{}
	var ask []ImageKey
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, img := range fresh.Images {
		if !listed[img.ImageKey] {
			continue // the server's report doesn't list it yet: the next report brings it
		}
		if Classify(img).Status != "" {
			continue // known without a request
		}
		if s := r.images[img.ImageKey]; s != nil {
			due := !s.retryAt.IsZero() && !now.Before(s.retryAt)
			if configChanged && s.status.Status == PrivateNoCredential {
				due = true
			}
			if !due {
				continue
			}
		}
		byKey[img.ImageKey] = img
		ask = append(ask, img.ImageKey)
	}
	return byKey, ask
}

// buildOne resolves, builds and uploads one image; it answers whether the image's status changed.
func (r *Runner) buildOne(ctx context.Context, img Image) bool {
	ctx, cancel := context.WithTimeout(ctx, BuildTimeout)
	defer cancel()
	start := time.Now()
	r.Log.Info("building", "ref", img.Ref, "digest", img.Digest, "platform", img.Platform)
	memory := r.memory()
	res, st := r.Images.Resolve(ctx, img)
	if st == nil && res.SizeBytes > r.Config.MaxImageBytes() {
		st = &Status{Status: TooLarge, Reason: "image", Detail: "larger than sbom_max_image_bytes; not pulled", SizeBytes: res.SizeBytes, LimitBytes: r.Config.MaxImageBytes()}
	}
	var sbom []byte
	packages := 0
	if st == nil {
		sbom, packages, st = r.Images.Build(ctx, img, res)
	}
	var why []any // a refused upload's answer
	if st == nil {
		st, why = r.upload(ctx, img, res, sbom)
	}
	mem := memory() // the build is over, whether it worked, failed or timed out
	r.Log.Info("built", append(append([]any{"ref", img.Ref, "platform", img.Platform, "packages", packages, "ms", time.Since(start).Milliseconds(),
		"sizeBytes", res.SizeBytes, "sbomBytes", len(sbom), "status", statusText(st)}, why...), mem...)...)
	return r.record(img.ImageKey, st)
}

func (r *Runner) memory() func() []any {
	if r.Memory == nil {
		return func() []any { return nil }
	}
	return r.Memory()
}

// upload sends one SBOM. A transient failure (no answer, a 5xx) leaves the image as it was, tried at the next run.
// When the server refused the SBOM or never answered, it also answers the built line's httpStatus and reason.
func (r *Runner) upload(ctx context.Context, img Image, res Resolved, sbom []byte) (*Status, []any) {
	if len(sbom) > MaxSBOMBytes {
		return &Status{Status: TooLarge, Reason: "sbom", Detail: fmt.Sprintf("the SBOM is %d bytes, over the API's 20 MB", len(sbom))}, nil
	}
	body, err := json.Marshal(Upload{Protocol: report.Protocol, Agent: r.Agent, Cluster: ID{r.info.ID}, SBOM: sbom, Image: UploadImage{
		Digest: img.Digest, Platform: img.Platform, ManifestDigest: res.ManifestDigest, ResolvedPlatform: res.ResolvedPlatform, Ref: img.Ref, SizeBytes: res.SizeBytes}})
	if err != nil {
		return &Status{Status: Error, Reason: "upload-rejected", Detail: err.Error()}, nil
	}
	gz, err := report.Gzip(body)
	if err != nil {
		return &Status{Status: Error, Reason: "upload-rejected", Detail: err.Error()}, nil
	}
	ans, err := r.retrying(ctx, "sbom upload", nil, func() (client.Result, error) { return r.Client.ImageSBOM(ctx, res.ManifestDigest, gz) })
	switch {
	case err != nil:
		r.Log.Warn("sbom not uploaded, tried again at the next run", "ref", img.Ref, "error", err)
		return &Status{Status: Error, Reason: "upload-rejected", Detail: detail(err)}, httpAnswer(0, detail(err))
	case ans.Status >= 200 && ans.Status < 300:
		return nil, nil
	case ans.Status == http.StatusRequestEntityTooLarge:
		return &Status{Status: TooLarge, Reason: "sbom", Detail: "the API refused the SBOM as too large (413)"}, httpAnswer(ans.Status, ans.Message)
	case ans.Status == http.StatusConflict:
		r.acked = "" // the server's report doesn't list this image: the next run sends the report
		return &Status{Status: Error, Reason: "upload-rejected", Detail: "the server's report doesn't list this image (409)"}, httpAnswer(ans.Status, ans.Message)
	default:
		return &Status{Status: Error, Reason: "upload-rejected", Detail: fmt.Sprintf("%d %s", ans.Status, ans.Message)}, httpAnswer(ans.Status, ans.Message)
	}
}

// httpAnswer is the built line's httpStatus (0: no answer) and reason (the server's message, or the error), cut at
// 200 characters.
func httpAnswer(status int, reason string) []any {
	if r := []rune(reason); len(r) > 200 {
		reason = string(r[:200])
	}
	return []any{"httpStatus", status, "reason", reason}
}

// record keeps an image's status and its next try; nil clears it. It answers whether the reported status changed.
func (r *Runner) record(k ImageKey, st *Status) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.images == nil {
		r.images = map[ImageKey]*imageState{}
	}
	old := r.images[k]
	if st == nil {
		delete(r.images, k)
		return old != nil
	}
	s := &imageState{status: *st, attempts: 1}
	if old != nil && old.status.Status == st.Status && old.status.Reason == st.Reason {
		s.attempts = old.attempts + 1
	}
	s.retryAt = RetryAt(*st, s.attempts, r.Now())
	r.images[k] = s
	return old == nil || old.status.Status != st.Status || old.status.Reason != st.Reason
}

// RetryAt is when an image with this status is tried again (the contract's "Image statuses"); zero is never in this
// process (a credential failure also comes back when the registry config changes).
func RetryAt(st Status, attempts int, now time.Time) time.Time {
	switch st.Reason {
	case "not-in-registry", "registry-unreachable", "no-credential", "credential-refused":
		return now.Add(24 * time.Hour)
	case "rate-limited":
		return now.Add(time.Hour)
	case "pull-failed", "catalog-failed", "timeout", "upload-rejected":
		switch attempts {
		case 1:
			return now // the next run
		case 2:
			return now.Add(time.Hour)
		case 3:
			return now.Add(6 * time.Hour)
		default:
			return now.Add(24 * time.Hour)
		}
	}
	return time.Time{} // too-large (the limit and the agent are fixed for the process), unsupported-platform
}

func statusText(st *Status) string {
	if st == nil {
		return "uploaded"
	}
	return st.Status + "/" + st.Reason
}

// retrying makes a request with the backoff on no answer, a 5xx or a 429, as server mode does. again, if set, runs
// after each backoff sleep, before the request is made again; an error from it ends the retries.
func (r *Runner) retrying(ctx context.Context, what string, again func() error, do func() (client.Result, error)) (client.Result, error) {
	for attempt := 0; ; attempt++ {
		res, err := do()
		retry := err != nil || res.Status >= 500 || res.Status == http.StatusTooManyRequests
		if !retry || attempt >= len(r.Backoff) {
			return res, err
		}
		wait := time.Duration(float64(r.Backoff[attempt]) * (0.8 + 0.4*rand.Float64()))
		if err == nil && res.Status == http.StatusTooManyRequests && res.RetryAfter > 0 {
			wait = min(res.RetryAfter, time.Hour)
		}
		r.Log.Warn(what+" failed, retrying", "status", res.Status, "error", errText(err), "in", wait.Round(time.Second))
		if err := r.Sleep(ctx, wait); err != nil {
			return res, err
		}
		if again != nil {
			if err := again(); err != nil {
				return res, err
			}
		}
	}
}

func (r *Runner) outcome(what string, res client.Result) error {
	switch {
	case res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden:
		return fmt.Errorf("%s: token rejected (%d, token %s): %s", what, res.Status, client.TokenHint(r.Config.Token), res.Message)
	case res.Status == http.StatusNotFound:
		return fmt.Errorf("%s: this FlawRook does not support cluster mode, or FLAWROOK_URL is wrong (404)", what)
	case res.Status == http.StatusUpgradeRequired:
		return fmt.Errorf("%s: upgrade the agent, the server no longer accepts protocol %d: %s", what, report.Protocol, res.Message)
	case res.Status >= 300 && res.Status < 400:
		return fmt.Errorf("%s: unexpected redirect (%d), not followed: check the url", what, res.Status)
	default:
		return fmt.Errorf("%s: %d %s", what, res.Status, res.Message)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Run loops until ctx ends: the first run once the lists are complete (after firstDelay), then every interval, and
// after a minute of quiet following a change in the cluster.
func (r *Runner) Run(ctx context.Context, interval, firstDelay time.Duration) error {
	r.Source.Start(ctx)
	r.Log.Info("started", "mode", "cluster", "url", r.Config.URL, "token", client.TokenHint(r.Config.Token), "cluster", r.info.ID[len(r.info.ID)-8:],
		"firstRunIn", firstDelay.Round(time.Second), "interval", interval)
	tick := time.NewTimer(firstDelay)
	quiet := time.NewTimer(time.Hour)
	quiet.Stop()
	paced := time.NewTimer(time.Hour)
	paced.Stop()
	defer tick.Stop()
	defer quiet.Stop()
	defer paced.Stop()
	started := false
	run := func(why Trigger) {
		at, err := r.Cycle(ctx, why)
		if err != nil && ctx.Err() == nil {
			r.Log.Error("run failed", "error", err)
		}
		if !at.IsZero() {
			paced.Reset(time.Until(at))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			started = true
			run(OnInterval)
			tick.Reset(interval)
		case <-r.Source.Changed():
			if started {
				quiet.Reset(Quiet)
			}
		case <-quiet.C:
			run(OnChange)
		case <-paced.C:
			run(OnChange)
		}
	}
}

// DryRun prints the report the agent would send for these pods and nodes (no SBOMs are built), and sends nothing.
func (r *Runner) DryRun(w io.Writer, pods []kube.Pod, nodes []kube.Node) error {
	body, err := json.Marshal(NewReport(r.Agent, r.info, Build(pods, nodes, r.scope(), nil)))
	if err != nil {
		return err
	}
	_, err = w.Write(append(body, '\n'))
	return err
}

// FirstDelay spreads clusters installed at once: up to a minute.
func FirstDelay() time.Duration { return time.Duration(rand.Int64N(int64(time.Minute) + 1)) }
