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
	"log/slog"
	"sync"
	"time"

	"flawrook.dev/agent/internal/kube"
)

// Source is the cluster's pods and nodes as the loop sees them.
type Source interface {
	// Start keeps the pods and nodes current until ctx ends.
	Start(ctx context.Context)
	// State is what is known now; complete is false after a list error or a watch gap, until a list succeeds: the
	// agent never reports from a partial view.
	State() (pods []kube.Pod, nodes []kube.Node, complete bool)
	// Changed is signalled after any change, coalesced.
	Changed() <-chan struct{}
}

// Watcher is the Source over the API: a list, then a watch from its resource version, of pods (cluster-wide) and
// of nodes. A watch the server ends is watched again; a watch error or a 410 lists again.
type Watcher struct {
	API   *kube.Client
	Log   *slog.Logger
	Sleep func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	pods    collection[kube.Pod]
	nodes   collection[kube.Node]
	changed chan struct{}
}

type collection[T any] struct {
	items    map[string]T
	complete bool
}

func (w *Watcher) Start(ctx context.Context) {
	w.mu.Lock()
	if w.changed == nil {
		w.changed = make(chan struct{}, 1)
	}
	w.mu.Unlock()
	go follow(ctx, w, "/api/v1/nodes", &w.nodes, func(n kube.Node) string { return n.Metadata.Name })
	go follow(ctx, w, "/api/v1/pods", &w.pods, func(p kube.Pod) string { return p.Metadata.Namespace + "/" + p.Metadata.Name })
}

func (w *Watcher) State() ([]kube.Pod, []kube.Node, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	pods := make([]kube.Pod, 0, len(w.pods.items))
	for _, p := range w.pods.items {
		pods = append(pods, p)
	}
	nodes := make([]kube.Node, 0, len(w.nodes.items))
	for _, n := range w.nodes.items {
		nodes = append(nodes, n)
	}
	return pods, nodes, w.pods.complete && w.nodes.complete
}

func (w *Watcher) Changed() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed == nil {
		w.changed = make(chan struct{}, 1)
	}
	return w.changed
}

func (w *Watcher) signal() {
	select {
	case w.changed <- struct{}{}:
	default:
	}
}

// follow lists and watches one collection until ctx ends.
func follow[T any](ctx context.Context, w *Watcher, path string, c *collection[T], key func(T) string) {
	for ctx.Err() == nil {
		items, rv, err := kube.List[T](ctx, w.API, path)
		if err != nil {
			if ctx.Err() == nil {
				w.Log.Warn("list failed, nothing is reported until it succeeds", "path", path, "error", err)
				_ = w.Sleep(ctx, 10*time.Second)
			}
			continue
		}
		w.mu.Lock()
		c.items, c.complete = map[string]T{}, true
		for _, it := range items {
			c.items[key(it)] = it
		}
		w.mu.Unlock()
		w.signal()
		for ctx.Err() == nil {
			rv, err = w.API.Watch(ctx, path, rv, func(ev kube.Event) {
				var it T
				if json.Unmarshal(ev.Object, &it) != nil {
					return
				}
				w.mu.Lock()
				if ev.Type == "DELETED" {
					delete(c.items, key(it))
				} else {
					c.items[key(it)] = it
				}
				w.mu.Unlock()
				w.signal()
			})
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, kube.ErrGone) {
					w.Log.Warn("watch failed, listing again", "path", path, "error", err)
				}
				w.mu.Lock()
				c.complete = false // a gap: nothing is reported until the list succeeds
				w.mu.Unlock()
				break
			}
		}
	}
}

// Lists reads the pods and nodes once, for --dry-run.
func Lists(ctx context.Context, api *kube.Client) ([]kube.Pod, []kube.Node, error) {
	pods, _, err := kube.List[kube.Pod](ctx, api, "/api/v1/pods")
	if err != nil {
		return nil, nil, err
	}
	nodes, _, err := kube.List[kube.Node](ctx, api, "/api/v1/nodes")
	return pods, nodes, err
}
