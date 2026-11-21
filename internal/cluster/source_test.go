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
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"flawrook.dev/agent/internal/kube"
)

// apiserver lists two pods and a node; each pods watch sends the next scripted batch of events, then holds the
// watch open until the test ends it. A "410" batch answers with a 410 ERROR event.
type apiserver struct {
	mu      sync.Mutex
	batches []string
	lists   map[string]int
	release chan struct{} // ends the open pods watch
	done    chan struct{} // ends every watch, at the test's end
}

func (a *apiserver) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	if q.Get("watch") != "1" {
		a.lists[r.URL.Path]++
	}
	a.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v1/nodes" && q.Get("watch") != "1":
		fmt.Fprint(w, `{"metadata":{"resourceVersion":"1"},"items":[{"metadata":{"name":"w1"},"status":{"nodeInfo":{"architecture":"arm64","operatingSystem":"linux"}}}]}`)
	case r.URL.Path == "/api/v1/pods" && q.Get("watch") != "1":
		fmt.Fprint(w, `{"metadata":{"resourceVersion":"5"},"items":[{"metadata":{"namespace":"shop","name":"a"}},{"metadata":{"namespace":"shop","name":"b"}}]}`)
	case r.URL.Path == "/api/v1/pods":
		a.mu.Lock()
		batch := ""
		if len(a.batches) > 0 {
			batch, a.batches = a.batches[0], a.batches[1:]
		}
		a.mu.Unlock()
		if batch == "410" {
			fmt.Fprint(w, `{"type":"ERROR","object":{"kind":"Status","code":410,"message":"too old"}}`+"\n")
			return
		}
		fmt.Fprint(w, batch)
		w.(http.Flusher).Flush()
		select {
		case <-a.release:
		case <-a.done:
		case <-r.Context().Done():
		}
	default: // the nodes watch: held open
		select {
		case <-a.done:
		case <-r.Context().Done():
		}
	}
}

func names(pods []kube.Pod) string {
	var n []string
	for _, p := range pods {
		n = append(n, p.Metadata.Name)
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

func TestWatcherListsWatchesAndRelists(t *testing.T) {
	a := &apiserver{lists: map[string]int{}, release: make(chan struct{}), done: make(chan struct{}), batches: []string{
		`{"type":"ADDED","object":{"metadata":{"namespace":"shop","name":"c","resourceVersion":"6"}}}` + "\n" +
			`{"type":"DELETED","object":{"metadata":{"namespace":"shop","name":"a","resourceVersion":"7"}}}` + "\n",
	}}
	srv := httptest.NewTLSServer(http.HandlerFunc(a.serve))
	defer srv.Close()
	defer close(a.done)
	token := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(token, []byte("t"), 0o600)
	api, err := kube.New(srv.URL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), token)
	if err != nil {
		t.Fatal(err)
	}
	w := &Watcher{API: api, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Sleep: func(context.Context, time.Duration) error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	wait := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				pods, nodes, complete := w.State()
				t.Fatalf("%s: pods %s, %d nodes, complete %v", what, names(pods), len(nodes), complete)
			}
			select {
			case <-w.Changed():
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait("the list and the watch's events", func() bool {
		pods, nodes, complete := w.State()
		return complete && len(nodes) == 1 && names(pods) == "b,c"
	})

	// A 410 on the next pods watch: incomplete until the relist, which brings the list's two pods back.
	a.mu.Lock()
	a.batches = []string{"410"}
	a.mu.Unlock()
	a.release <- struct{}{} // end the current pods watch; the watcher watches again and gets the 410
	wait("the relist after a 410", func() bool {
		a.mu.Lock()
		relisted := a.lists["/api/v1/pods"] >= 2
		a.mu.Unlock()
		pods, _, complete := w.State()
		return relisted && complete && names(pods) == "a,b"
	})
}
