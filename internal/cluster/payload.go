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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"flawrook.dev/agent/internal/report"
)

// Mode is every cluster body's agent.mode.
const Mode = "cluster"

// Agent is a cluster body's "agent".
type Agent struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Mode    string `json:"mode"`
}

// Info is the report's "cluster".
type Info struct {
	ID      string  `json:"id"`
	Name    *string `json:"name"`    // null when no cluster_name is set
	Version *string `json:"version"` // /version's gitVersion, null when it can't be read
	Scope   Scope   `json:"scope"`
}

// Report is POST /api/v1/agent/cluster/report's body, before gzip.
type Report struct {
	Protocol   int        `json:"protocol"`
	Agent      Agent      `json:"agent"`
	Cluster    Info       `json:"cluster"`
	Nodes      []Node     `json:"nodes"`
	Workloads  []Workload `json:"workloads"`
	Images     []Image    `json:"images"`
	ReportHash string     `json:"reportHash"`
}

// Heartbeat is POST /api/v1/agent/cluster/heartbeat's body.
type Heartbeat struct {
	Protocol   int    `json:"protocol"`
	Agent      Agent  `json:"agent"`
	Cluster    IDName `json:"cluster"`
	ReportHash string `json:"reportHash"`
}

type IDName struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

type ID struct {
	ID string `json:"id"`
}

// Needed is POST /api/v1/agent/cluster/images/needed's body; the answer lists the images the workspace has no
// SBOM for.
type Needed struct {
	Protocol int        `json:"protocol"`
	Agent    Agent      `json:"agent"`
	Cluster  ID         `json:"cluster"`
	Images   []ImageKey `json:"images"`
}

type NeededAnswer struct {
	Needed []ImageKey `json:"needed"`
}

// Upload is POST /api/v1/agent/cluster/images/{manifestDigest}/sbom's body, before gzip.
type Upload struct {
	Protocol int             `json:"protocol"`
	Agent    Agent           `json:"agent"`
	Cluster  ID              `json:"cluster"`
	Image    UploadImage     `json:"image"`
	SBOM     json.RawMessage `json:"sbom"`
}

type UploadImage struct {
	Digest           string `json:"digest"`
	Platform         string `json:"platform"`
	ManifestDigest   string `json:"manifestDigest"`
	ResolvedPlatform string `json:"resolvedPlatform"` // the index entry picked, variant included; for display
	Ref              string `json:"ref"`
	SizeBytes        int64  `json:"sizeBytes"` // the manifest's compressed layers
}

// NewReport assembles a report around a snapshot, with its hash. Empty lists are sent as [], never null.
func NewReport(agent Agent, info Info, snap Snapshot) Report {
	r := Report{Protocol: report.Protocol, Agent: agent, Cluster: info, Nodes: snap.Nodes, Workloads: snap.Workloads, Images: snap.Images}
	if r.Nodes == nil {
		r.Nodes = []Node{}
	}
	if r.Workloads == nil {
		r.Workloads = []Workload{}
	}
	if r.Images == nil {
		r.Images = []Image{}
	}
	for i := range r.Workloads {
		if r.Workloads[i].Containers == nil {
			r.Workloads[i].Containers = []Container{}
		}
	}
	if r.Cluster.Scope.Include == nil {
		r.Cluster.Scope.Include = []string{}
	}
	if r.Cluster.Scope.Exclude == nil {
		r.Cluster.Scope.Exclude = []string{}
	}
	r.ReportHash = Hash(r)
	return r
}

// HeartbeatFor stands for a report the server acknowledged.
func HeartbeatFor(r Report) Heartbeat {
	return Heartbeat{Protocol: report.Protocol, Agent: r.Agent, Cluster: IDName{ID: r.Cluster.ID, Name: r.Cluster.Name}, ReportHash: r.ReportHash}
}

// Hash is the report's controller-level hash (the contract's "Report hash"): the agent's version; the cluster's
// id, name, version and scope; the set of distinct node facts without names or counts; the workloads with their
// container rows; the images with their ref, status and reason. Never pod names or counts, node names or counts,
// detail, sizes or manifest digests, so autoscaling, restarts and rescheduling send only heartbeats.
func Hash(r Report) string {
	type nodeFacts struct {
		Kubelet, Runtime, OSImage, Kernel, OS, Arch, Provider string
	}
	type image struct {
		Digest, Platform, Ref, Status, Reason string
	}
	type canonical struct {
		AgentVersion string
		ID           string
		Name         string
		Version      string
		Include      []string
		Exclude      []string
		Nodes        []nodeFacts
		Workloads    []Workload
		Images       []image
	}
	c := canonical{AgentVersion: r.Agent.Version, ID: r.Cluster.ID, Name: deref(r.Cluster.Name), Version: deref(r.Cluster.Version),
		Include: sorted(r.Cluster.Scope.Include), Exclude: sorted(r.Cluster.Scope.Exclude)}
	seen := map[nodeFacts]bool{}
	for _, n := range r.Nodes {
		f := nodeFacts{n.Kubelet, n.Runtime, n.OSImage, n.Kernel, n.OS, n.Arch, deref(n.Provider)}
		if !seen[f] {
			seen[f] = true
			c.Nodes = append(c.Nodes, f)
		}
	}
	sort.Slice(c.Nodes, func(i, j int) bool {
		a, b := c.Nodes[i], c.Nodes[j]
		return joinKey(a.Kubelet, a.Runtime, a.OSImage, a.Kernel, a.OS, a.Arch, a.Provider) < joinKey(b.Kubelet, b.Runtime, b.OSImage, b.Kernel, b.OS, b.Arch, b.Provider)
	})
	for _, w := range r.Workloads { // already sorted by Build, rows too; sorted again so the hash never depends on it
		rows := append([]Container(nil), w.Containers...)
		sort.Slice(rows, func(i, j int) bool { return lessContainer(rows[i], rows[j]) })
		c.Workloads = append(c.Workloads, Workload{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Containers: rows})
	}
	sort.Slice(c.Workloads, func(i, j int) bool {
		a, b := c.Workloads[i], c.Workloads[j]
		return joinKey(a.Namespace, a.Kind, a.Name) < joinKey(b.Namespace, b.Kind, b.Name)
	})
	for _, img := range r.Images {
		c.Images = append(c.Images, image{img.Digest, img.Platform, img.Ref, img.Status.Status, img.Reason})
	}
	sort.Slice(c.Images, func(i, j int) bool {
		return joinKey(c.Images[i].Digest, c.Images[i].Platform) < joinKey(c.Images[j].Digest, c.Images[j].Platform)
	})
	raw, _ := json.Marshal(c) // fixed field order, no whitespace
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func joinKey(parts ...string) string {
	out := ""
	for _, p := range parts {
		out += p + "\x00"
	}
	return out
}

func sorted(list []string) []string {
	out := append([]string{}, list...)
	sort.Strings(out)
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
