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

// Package kube is cluster mode's Kubernetes API client: GET, paged lists and watches over plain HTTP, with the
// pod's own ServiceAccount. Its transport never uses a proxy, whatever HTTPS_PROXY says: the apiserver is reached
// by its in-cluster IP. The agent may only get kube-system and list and watch pods and nodes.
package kube

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ServiceAccountDir is where the kubelet mounts the pod's token and the cluster's CA.
const ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// ErrGone is a 410: the resource version is too old, so the caller lists again.
var ErrGone = errors.New("resource version expired (410): list again")

type Client struct {
	base      string
	tokenFile string
	http      *http.Client
}

// InCluster builds the client from the pod's environment and ServiceAccount.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not in a cluster: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are unset")
	}
	ca, err := os.ReadFile(ServiceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	return New("https://"+net.JoinHostPort(host, port), ca, ServiceAccountDir+"/token")
}

// New builds a client for an apiserver address, its CA and a token file.
func New(base string, caPEM []byte, tokenFile string) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the cluster's CA has no PEM certificate")
	}
	transport := &http.Transport{
		Proxy:               nil, // never a proxy: see the package comment
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 30 * time.Second,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return &Client{base: strings.TrimRight(base, "/"), tokenFile: tokenFile, http: &http.Client{Transport: transport}}, nil
}

// StatusError is an answer other than 200.
type StatusError struct {
	Code    int
	Path    string
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: %d %s", e.Path, e.Code, e.Message) }

// open makes one GET. The token is read on every request: the kubelet rotates the projected token (hourly by
// default) and replaces the file.
func (c *Client) open(ctx context.Context, path string) (io.ReadCloser, error) {
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("the ServiceAccount token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		var status struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &status) != nil || status.Message == "" {
			status.Message = strings.TrimSpace(string(raw))
		}
		if res.StatusCode == http.StatusGone {
			return nil, ErrGone
		}
		return nil, &StatusError{Code: res.StatusCode, Path: strings.SplitN(path, "?", 2)[0], Message: status.Message}
	}
	return res.Body, nil
}

// Get decodes one object.
func (c *Client) Get(ctx context.Context, path string, v any) error {
	body, err := c.open(ctx, path)
	if err != nil {
		return err
	}
	defer body.Close()
	return json.NewDecoder(body).Decode(v)
}

// PageSize bounds each list request, so a large cluster's pods never sit in memory as one response.
const PageSize = 500

// List reads a collection page by page into T, which holds only the fields the agent uses, and returns the
// list's resource version for a watch. A 410 on a later page (the continue token expired) is ErrGone.
func List[T any](ctx context.Context, c *Client, path string) ([]T, string, error) {
	var items []T
	cont := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(PageSize)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := c.Get(ctx, path+"?"+q.Encode(), &page); err != nil {
			return nil, "", err
		}
		items = append(items, page.Items...)
		if page.Metadata.Continue == "" {
			return items, page.Metadata.ResourceVersion, nil
		}
		cont = page.Metadata.Continue
	}
}

// Event is one watch event: ADDED, MODIFIED or DELETED with its object.
type Event struct {
	Type   string
	Object json.RawMessage
}

// Watch streams a collection's events from resourceVersion rv until the server ends the watch (its 300 s timeout)
// or ctx ends, and returns the last resource version seen. Bookmarks only move it. An ERROR event is ErrGone for a
// 410, else an error: either way the caller lists again.
func (c *Client) Watch(ctx context.Context, path, rv string, fn func(Event)) (string, error) {
	q := url.Values{"watch": {"1"}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"300"}, "resourceVersion": {rv}}
	body, err := c.open(ctx, path+"?"+q.Encode())
	if err != nil {
		return rv, err
	}
	defer body.Close()
	dec := json.NewDecoder(bufio.NewReader(body))
	for {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return rv, ctx.Err()
			}
			return rv, nil // the server ended the watch: watch again from rv
		}
		if ev.Type == "ERROR" {
			var status struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(ev.Object, &status)
			if status.Code == http.StatusGone {
				return rv, ErrGone
			}
			return rv, fmt.Errorf("watch %s: %d %s", path, status.Code, status.Message)
		}
		var meta struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if json.Unmarshal(ev.Object, &meta) == nil && meta.Metadata.ResourceVersion != "" {
			rv = meta.Metadata.ResourceVersion
		}
		if ev.Type != "BOOKMARK" {
			fn(Event{Type: ev.Type, Object: ev.Object})
		}
	}
}
