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

// Package report builds the payloads of the agent API, protocol 1: the full report and the heartbeat.
package report

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"flawrook.dev/agent/internal/hostinfo"
)

// Protocol is sent in every request, as the FlawRook-Agent-Protocol header and in the body.
const Protocol = 1

type Agent struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Report is POST /api/v1/agent/report's body, before gzip.
type Report struct {
	Protocol   int             `json:"protocol"`
	Agent      Agent           `json:"agent"`
	Host       hostinfo.Info   `json:"host"`
	ReportHash string          `json:"reportHash"`
	SBOM       json.RawMessage `json:"sbom"`
}

// Heartbeat is POST /api/v1/agent/heartbeat's body.
type Heartbeat struct {
	Protocol   int           `json:"protocol"`
	Agent      Agent         `json:"agent"`
	Host       HeartbeatHost `json:"host"`
	ReportHash string        `json:"reportHash"`
}

type HeartbeatHost struct {
	HostID   string `json:"hostId"`
	Hostname string `json:"hostname"`
}

// New builds a report around Syft's CycloneDX JSON, with its hash.
func New(agent Agent, host hostinfo.Info, sbom []byte) (Report, error) {
	hash, err := Hash(agent, host, sbom)
	if err != nil {
		return Report{}, err
	}
	return Report{Protocol: Protocol, Agent: agent, Host: host, ReportHash: hash, SBOM: sbom}, nil
}

// HeartbeatFor is the heartbeat that stands for a report the server acknowledged.
func HeartbeatFor(r Report) Heartbeat {
	return Heartbeat{Protocol: Protocol, Agent: r.Agent, Host: HeartbeatHost{HostID: r.Host.HostID, Hostname: r.Host.Hostname}, ReportHash: r.ReportHash}
}

// Hash changes exactly when the inventory, the kernel, os-release, the hostname or the agent's version
// does. The SBOM's serial number and timestamp differ on every run and are left out, and every array is
// taken in a canonical order, so Syft listing the same packages in another order changes nothing.
func Hash(agent Agent, host hostinfo.Info, sbom []byte) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return "", fmt.Errorf("sbom: %w", err)
	}
	delete(doc, "serialNumber")
	if meta, ok := doc["metadata"].(map[string]any); ok {
		delete(meta, "timestamp")
	}
	canonical, err := json.Marshal(map[string]any{
		"agentVersion": agent.Version,
		"hostname":     host.Hostname,
		"kernel":       host.Kernel,
		"osRelease":    host.OSRelease,
		"sbom":         canonicalize(doc),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// canonicalize sorts every array by its elements' JSON; objects are sorted by encoding/json already.
func canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = canonicalize(e)
		}
		return t
	case []any:
		keys := make([]string, len(t))
		for i, e := range t {
			t[i] = canonicalize(e)
			b, _ := json.Marshal(t[i])
			keys[i] = string(b)
		}
		sort.Sort(byKey{t, keys})
		return t
	default:
		return v
	}
}

type byKey struct {
	items []any
	keys  []string
}

func (b byKey) Len() int           { return len(b.items) }
func (b byKey) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b byKey) Swap(i, j int) {
	b.items[i], b.items[j] = b.items[j], b.items[i]
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
}

// JSON is the exact body before gzip: what --dry-run prints.
func (r Report) JSON() ([]byte, error) { return json.Marshal(r) }

// Gzip compresses a body for Content-Encoding: gzip.
func Gzip(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
