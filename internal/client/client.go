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

// Package client sends the agent's two requests to FlawRook: outbound HTTPS only, through a proxy when
// one is set, trusting the system's CAs plus an optional bundle.
package client

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"

	"flawrook.dev/agent/internal/config"
	"flawrook.dev/agent/internal/report"
)

const (
	ReportPath    = "/api/v1/agent/report"
	HeartbeatPath = "/api/v1/agent/heartbeat"
	ProtocolKey   = "FlawRook-Agent-Protocol"

	// Cluster mode's routes (the cluster contract, draft 2).
	ClusterReportPath    = "/api/v1/agent/cluster/report"
	ClusterHeartbeatPath = "/api/v1/agent/cluster/heartbeat"
	ImagesNeededPath     = "/api/v1/agent/cluster/images/needed"
)

// The answer bodies read: images/needed may list up to 10,000 images, every other answer is small.
const (
	answerLimit = 64 << 10
	neededLimit = 4 << 20
)

// Result is the server's answer: its status and what the contract lets it carry.
type Result struct {
	Status     int
	RetryAfter time.Duration // 429's Retry-After, zero when absent
	Message    string
	URL        string // 202: the host's page
	ReportHash string // 202: the hash the server stored
	Location   string // a 3xx's Location: never followed
	Body       []byte // the answer as sent, for the routes whose answer carries more (images/needed)
}

type Client struct {
	base      string
	token     string
	userAgent string
	http      *http.Client
}

// New builds a client for a config. Each config load builds a new one, so a SIGHUP's proxy or CA applies.
func New(c config.Config, userAgent string) (*Client, error) {
	transport, err := Transport(c)
	if err != nil {
		return nil, err
	}
	return &Client{base: c.URL, token: c.Token, userAgent: userAgent, http: &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
		// Never follow a redirect: Go would send the token along to the same host even over plain http, and
		// the body again on a 307 or 308. FlawRook's API never redirects, so a 3xx is answered as is.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Transport is the agent's outbound transport for a config: the system's CAs plus ca_file, and the config's proxy.
// FlawRook's client uses it, and so does cluster mode's registry client.
func Transport(c config.Config) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no PEM certificate in it", c.CAFile)
		}
	}
	proxy := ProxyFunc(c)
	return &http.Transport{
		Proxy:               func(r *http.Request) (*url.URL, error) { return proxy(r.URL) },
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 30 * time.Second,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
	}, nil
}

// ProxyFunc reads the config's proxy settings, not the process's: Go's ProxyFromEnvironment reads the
// environment once per process, so a SIGHUP couldn't change it.
func ProxyFunc(c config.Config) func(*url.URL) (*url.URL, error) {
	return (&httpproxy.Config{HTTPSProxy: c.HTTPSProxy, NoProxy: c.NoProxy}).ProxyFunc()
}

// Report sends a gzip-compressed report.
func (c *Client) Report(ctx context.Context, gz []byte) (Result, error) {
	return c.post(ctx, ReportPath, gz, true)
}

// Heartbeat sends a heartbeat (plain JSON, about 300 bytes).
func (c *Client) Heartbeat(ctx context.Context, body []byte) (Result, error) {
	return c.post(ctx, HeartbeatPath, body, false)
}

// ClusterReport sends a gzip-compressed cluster report.
func (c *Client) ClusterReport(ctx context.Context, gz []byte) (Result, error) {
	return c.post(ctx, ClusterReportPath, gz, true)
}

// ClusterHeartbeat sends a cluster heartbeat (plain JSON, about 400 bytes).
func (c *Client) ClusterHeartbeat(ctx context.Context, body []byte) (Result, error) {
	return c.post(ctx, ClusterHeartbeatPath, body, false)
}

// ImagesNeeded asks which images the workspace has no SBOM for; the answer is in Result.Body.
func (c *Client) ImagesNeeded(ctx context.Context, body []byte) (Result, error) {
	return c.postLimit(ctx, ImagesNeededPath, body, false, neededLimit)
}

// ImageSBOM uploads one image's gzip-compressed SBOM under its platform manifest digest.
func (c *Client) ImageSBOM(ctx context.Context, manifestDigest string, gz []byte) (Result, error) {
	return c.post(ctx, "/api/v1/agent/cluster/images/"+manifestDigest+"/sbom", gz, true)
}

// post returns an error only when no answer came; any status is a Result.
func (c *Client) post(ctx context.Context, path string, body []byte, gzipped bool) (Result, error) {
	return c.postLimit(ctx, path, body, gzipped, answerLimit)
}

func (c *Client) postLimit(ctx context.Context, path string, body []byte, gzipped bool, limit int64) (Result, error) {
	if c.token == "" {
		return Result{}, errors.New("no token: set FLAWROOK_TOKEN, or token in the config file")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set(ProtocolKey, strconv.Itoa(report.Protocol))
	res, err := c.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, limit))
	var answer struct {
		Message    string `json:"message"`
		URL        string `json:"url"`
		ReportHash string `json:"reportHash"`
	}
	_ = json.Unmarshal(raw, &answer)
	if answer.Message == "" && res.StatusCode >= 400 {
		answer.Message = strings.TrimSpace(string(raw))
	}
	return Result{Status: res.StatusCode, RetryAfter: retryAfter(res.Header.Get("Retry-After")), Message: answer.Message, URL: answer.URL, ReportHash: answer.ReportHash, Location: res.Header.Get("Location"), Body: raw}, nil
}

// retryAfter reads seconds or an HTTP date.
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// TokenHint is the most of a token the agent ever logs: its last 4 characters.
func TokenHint(token string) string {
	if len(token) <= 4 {
		return "…"
	}
	return "…" + token[len(token)-4:]
}
