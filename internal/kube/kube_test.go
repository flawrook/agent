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

package kube

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// apiserver answers a few paths the way the API does, and records the tokens it was sent.
type apiserver struct {
	mu     sync.Mutex
	tokens []string
	paths  []string
}

func (a *apiserver) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.tokens = append(a.tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	a.paths = append(a.paths, r.URL.RequestURI())
	a.mu.Unlock()
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/api/v1/namespaces/kube-system":
		fmt.Fprint(w, `{"metadata":{"name":"kube-system","uid":"3c8d3f0e-1b2a-4c5d-8e9f-0a1b2c3d4e5f"}}`)
	case r.URL.Path == "/api/v1/namespaces/forbidden":
		w.WriteHeader(403)
		fmt.Fprint(w, `{"kind":"Status","message":"namespaces \"forbidden\" is forbidden: User cannot get resource","code":403}`)
	case r.URL.Path == "/api/v1/pods" && q.Get("watch") == "1":
		if q.Get("resourceVersion") == "old" {
			fmt.Fprint(w, `{"type":"ERROR","object":{"kind":"Status","code":410,"message":"too old resource version"}}`+"\n")
			return
		}
		fmt.Fprint(w, `{"type":"ADDED","object":{"metadata":{"name":"a","resourceVersion":"11"}}}`+"\n")
		fmt.Fprint(w, `{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"12"}}}`+"\n")
		fmt.Fprint(w, `{"type":"DELETED","object":{"metadata":{"name":"b","resourceVersion":"13"}}}`+"\n")
	case r.URL.Path == "/api/v1/pods":
		if q.Get("limit") != "500" {
			w.WriteHeader(400)
			return
		}
		switch q.Get("continue") {
		case "":
			fmt.Fprint(w, `{"metadata":{"resourceVersion":"9","continue":"page2"},"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`)
		case "page2":
			fmt.Fprint(w, `{"metadata":{"resourceVersion":"10"},"items":[{"metadata":{"name":"c"}}]}`)
		default:
			w.WriteHeader(410)
			fmt.Fprint(w, `{"kind":"Status","code":410,"message":"the provided continue parameter is too old"}`)
		}
	default:
		w.WriteHeader(404)
	}
}

func newClient(t *testing.T) (*Client, *apiserver, string) {
	t.Helper()
	a := &apiserver{}
	srv := httptest.NewTLSServer(http.HandlerFunc(a.serve))
	t.Cleanup(srv.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), token)
	if err != nil {
		t.Fatal(err)
	}
	return c, a, token
}

func TestGetRereadsTheTokenAndNeverUsesAProxy(t *testing.T) {
	c, a, token := newClient(t)
	// The transport has no proxy function at all, whatever HTTPS_PROXY says. (A dead proxy in the environment
	// couldn't show it here: Go never proxies a loopback address, and the stand-in is on 127.0.0.1.)
	if p := c.http.Transport.(*http.Transport).Proxy; p != nil {
		t.Fatal("the apiserver transport has a proxy function")
	}
	var ns Namespace
	if err := c.Get(context.Background(), "/api/v1/namespaces/kube-system", &ns); err != nil {
		t.Fatal(err)
	}
	if ns.Metadata.UID != "3c8d3f0e-1b2a-4c5d-8e9f-0a1b2c3d4e5f" {
		t.Fatalf("uid %q", ns.Metadata.UID)
	}
	// The kubelet rotates the projected token: the next request sends the new one.
	if err := os.WriteFile(token, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), "/api/v1/namespaces/kube-system", &ns); err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.tokens, ",") != "first,second" {
		t.Fatalf("tokens sent %v", a.tokens)
	}
}

func TestStatusErrors(t *testing.T) {
	c, _, _ := newClient(t)
	var ns Namespace
	err := c.Get(context.Background(), "/api/v1/namespaces/forbidden", &ns)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || !strings.Contains(se.Message, "is forbidden") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := List[Pod](context.Background(), c, "/api/v1/pods?expired"); err == nil {
		t.Fatal("a malformed path listed")
	}
}

func TestListPagesThroughContinue(t *testing.T) {
	c, a, _ := newClient(t)
	pods, rv, err := List[Pod](context.Background(), c, "/api/v1/pods")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pods {
		names = append(names, p.Metadata.Name)
	}
	if strings.Join(names, ",") != "a,b,c" || rv != "10" {
		t.Fatalf("items %v, rv %q", names, rv)
	}
	if len(a.paths) != 2 || !strings.Contains(a.paths[1], "continue=page2") {
		t.Fatalf("requests %v", a.paths)
	}
}

func TestWatchFollowsResourceVersionsAndSignalsGone(t *testing.T) {
	c, a, _ := newClient(t)
	var events []string
	rv, err := c.Watch(context.Background(), "/api/v1/pods", "10", func(e Event) { events = append(events, e.Type) })
	if err != nil {
		t.Fatal(err)
	}
	// The bookmark moves the resource version but reaches no handler.
	if strings.Join(events, ",") != "ADDED,DELETED" || rv != "13" {
		t.Fatalf("events %v, rv %q", events, rv)
	}
	if q := a.paths[len(a.paths)-1]; !strings.Contains(q, "allowWatchBookmarks=true") || !strings.Contains(q, "timeoutSeconds=300") || !strings.Contains(q, "resourceVersion=10") {
		t.Fatalf("watch query %s", q)
	}
	if _, err := c.Watch(context.Background(), "/api/v1/pods", "old", func(Event) {}); !errors.Is(err, ErrGone) {
		t.Fatalf("a 410 event gave %v", err)
	}
}

func TestNewRefusesACAWithoutACertificate(t *testing.T) {
	if _, err := New("https://10.0.0.1:443", []byte("not a pem"), "/dev/null"); err == nil {
		t.Fatal("accepted")
	}
}
