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

// Package cluster is the agent's cluster mode (the cluster contract, draft 2): it watches the cluster's pods and
// nodes, reports its workloads, images and node facts at controller level, and builds each new image's SBOM.
package cluster

import (
	"regexp"
	"sort"
	"strings"

	"flawrook.dev/agent/internal/kube"
)

// Node is one node's facts, as the report carries them.
type Node struct {
	Name     string  `json:"name"`
	Kubelet  string  `json:"kubelet"`
	Runtime  string  `json:"runtime"`
	OSImage  string  `json:"osImage"`
	Kernel   string  `json:"kernel"`
	OS       string  `json:"os"`
	Arch     string  `json:"arch"`
	Provider *string `json:"provider"` // only the scheme of spec.providerID: the rest holds instance ids
}

// Container is one row of a workload: one distinct (name, init, image, digest, platform) among its pods.
type Container struct {
	Name     string `json:"name"`
	Init     bool   `json:"init"`
	Image    string `json:"image"` // as written in the pod spec
	Digest   string `json:"digest"`
	Platform string `json:"platform"`
}

type Workload struct {
	Namespace  string      `json:"namespace"`
	Kind       string      `json:"kind"`
	Name       string      `json:"name"`
	Containers []Container `json:"containers"`
}

// ImageKey is what the server keys an image by.
type ImageKey struct {
	Digest   string `json:"digest"`
	Platform string `json:"platform"`
}

// Status says why an image has no SBOM; the zero value is a scannable image.
type Status struct {
	Status     string `json:"status,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	SizeBytes  int64  `json:"sizeBytes,omitempty"`
	LimitBytes int64  `json:"limitBytes,omitempty"`
}

// Image is one distinct (digest, platform) some container runs.
type Image struct {
	ImageKey
	Ref string `json:"ref"` // the smallest of the runtime's references, so pod order never moves it
	Status
	Repo string `json:"-"` // where it is pulled from: the imageID's repository, the smallest one
}

// Scope is the namespace filter, by exact name. Both empty means every namespace.
type Scope struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

func (s Scope) covers(namespace string) bool {
	if len(s.Include) > 0 && !contains(s.Include, namespace) {
		return false
	}
	return !contains(s.Exclude, namespace)
}

// Snapshot is the cluster at controller level: what a report sends.
type Snapshot struct {
	Nodes     []Node
	Workloads []Workload
	Images    []Image
}

// Status values (the contract's "Image statuses").
const (
	NotPullable         = "not-pullable"
	PrivateNoCredential = "private-no-credential"
	TooLarge            = "too-large"
	Error               = "error"
)

var (
	digestFormat = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)
	// kind's preload and `kind load` / `ctr import` name images after the import's date, with no registry behind
	// them. Docker Hub answers 401 for a missing repository as for a private one, so these are classified first.
	importName = regexp.MustCompile(`^(docker\.io/library/)?import-\d{4}-\d{2}-\d{2}$`)
	// A CronJob names its Jobs <cronjob>-<scheduled time in minutes since the epoch>: 8 digits until 2160.
	cronJobSuffix = regexp.MustCompile(`^(.+)-\d{8,}$`)
)

// ParseImageID splits a container status's imageID into its repository and digest. An id with no repository
// ("sha256:…", the runtime's own image id) has an empty repo. ok is false for anything else, or no id yet.
func ParseImageID(imageID string) (repo, digest string, ok bool) {
	id := strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "docker://")
	if i := strings.LastIndex(id, "@"); i >= 0 {
		repo, id = id[:i], id[i+1:]
	}
	if !digestFormat.MatchString(id) {
		return "", "", false
	}
	return repo, id, true
}

// Owner is a pod's workload, from the pod alone: the agent may not read ReplicaSets or Jobs. Only the controller
// ownerReference counts.
func Owner(p kube.Pod) (kind, name string) {
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		switch o.Kind {
		case "ReplicaSet":
			if h := p.Metadata.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Deployment", strings.TrimSuffix(o.Name, "-"+h)
			}
			if h := p.Metadata.Labels["rollouts-pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Rollout", strings.TrimSuffix(o.Name, "-"+h)
			}
			return "ReplicaSet", o.Name
		case "Job":
			if m := cronJobSuffix.FindStringSubmatch(o.Name); m != nil {
				return "CronJob", m[1]
			}
			return "Job", o.Name
		case "Node": // a static pod's mirror
			if strings.HasSuffix(p.Metadata.Name, "-"+o.Name) {
				return "StaticPod", strings.TrimSuffix(p.Metadata.Name, "-"+o.Name)
			}
			return "StaticPod", p.Metadata.Name
		default:
			return o.Kind, o.Name
		}
	}
	if g := strings.TrimSuffix(p.Metadata.GenerateName, "-"); g != "" {
		return "Pod", g
	}
	return "Pod", p.Metadata.Name
}

// NodeOf is a node's facts.
func NodeOf(n kube.Node) Node {
	info := n.Status.NodeInfo
	node := Node{Name: n.Metadata.Name, Kubelet: info.KubeletVersion, Runtime: info.ContainerRuntimeVersion, OSImage: info.OSImage,
		Kernel: info.KernelVersion, OS: info.OperatingSystem, Arch: info.Architecture}
	if i := strings.Index(n.Spec.ProviderID, "://"); i > 0 {
		scheme := n.Spec.ProviderID[:i]
		node.Provider = &scheme
	}
	return node
}

// Build makes the snapshot of the pods and nodes in scope. statuses holds what the registry and builds found for
// images; images classified without a request (no repository, an import name, a Windows node) get theirs here.
func Build(pods []kube.Pod, nodes []kube.Node, scope Scope, statuses map[ImageKey]Status) Snapshot {
	var snap Snapshot
	platforms := map[string]string{}
	for _, n := range nodes {
		node := NodeOf(n)
		snap.Nodes = append(snap.Nodes, node)
		platforms[node.Name] = node.OS + "/" + node.Arch
	}
	sort.Slice(snap.Nodes, func(i, j int) bool { return snap.Nodes[i].Name < snap.Nodes[j].Name })

	type wkey struct{ ns, kind, name string }
	workloads := map[wkey]map[Container]bool{}
	images := map[ImageKey]*Image{}
	for _, p := range pods {
		if !scope.covers(p.Metadata.Namespace) {
			continue
		}
		platform, ok := platforms[p.Spec.NodeName]
		if !ok {
			continue // not scheduled yet, or its node just left: the next event brings it
		}
		kind, name := Owner(p)
		k := wkey{p.Metadata.Namespace, kind, name}
		add := func(specs []kube.ContainerSpec, states []kube.ContainerStatus, init bool) {
			for _, cs := range states {
				repo, digest, ok := ParseImageID(cs.ImageID)
				if !ok {
					continue // still waiting: no image yet
				}
				c := Container{Name: cs.Name, Init: init, Image: specImage(specs, cs.Name, cs.Image), Digest: digest, Platform: platform}
				if workloads[k] == nil {
					workloads[k] = map[Container]bool{}
				}
				workloads[k][c] = true
				ik := ImageKey{digest, platform}
				img := images[ik]
				if img == nil {
					img = &Image{ImageKey: ik, Ref: cs.Image, Repo: repo}
					images[ik] = img
				}
				img.Ref = smaller(img.Ref, cs.Image)
				img.Repo = smaller(img.Repo, repo)
			}
		}
		add(p.Spec.Containers, p.Status.ContainerStatuses, false)
		add(p.Spec.InitContainers, p.Status.InitContainerStatuses, true)
	}

	for k, rows := range workloads {
		w := Workload{Namespace: k.ns, Kind: k.kind, Name: k.name}
		for c := range rows {
			w.Containers = append(w.Containers, c)
		}
		sort.Slice(w.Containers, func(i, j int) bool { return lessContainer(w.Containers[i], w.Containers[j]) })
		snap.Workloads = append(snap.Workloads, w)
	}
	sort.Slice(snap.Workloads, func(i, j int) bool {
		a, b := snap.Workloads[i], snap.Workloads[j]
		return a.Namespace+"\x00"+a.Kind+"\x00"+a.Name < b.Namespace+"\x00"+b.Kind+"\x00"+b.Name
	})
	for _, img := range images {
		img.Status = Classify(*img)
		if img.Status.Status == "" {
			img.Status = statuses[img.ImageKey]
		}
		snap.Images = append(snap.Images, *img)
	}
	sort.Slice(snap.Images, func(i, j int) bool {
		a, b := snap.Images[i], snap.Images[j]
		return a.Digest < b.Digest || (a.Digest == b.Digest && a.Platform < b.Platform)
	})
	return snap
}

// Classify gives the statuses known without a request: no repository digest (the runtime's image id, or a kind
// or ctr import name), and a Windows node's image. Anything else is for the registry to say.
func Classify(img Image) Status {
	switch {
	case img.Repo == "":
		return Status{Status: NotPullable, Reason: "no-registry-digest", Detail: "no repository digest: the image was loaded into the node, not pulled"}
	case importName.MatchString(img.Repo):
		return Status{Status: NotPullable, Reason: "no-registry-digest", Detail: "preloaded or imported image (" + img.Repo + "), no registry behind it"}
	case strings.HasPrefix(img.Platform, "windows/"):
		return Status{Status: Error, Reason: "unsupported-platform", Detail: "Windows images aren't scanned"}
	}
	return Status{}
}

// Scannable says an image may be asked for and built: no status of its own.
func (img Image) Scannable() bool { return img.Status.Status == "" }

func specImage(specs []kube.ContainerSpec, name, fallback string) string {
	for _, s := range specs {
		if s.Name == name {
			return s.Image
		}
	}
	return fallback
}

func lessContainer(a, b Container) bool {
	ka := []string{a.Name, boolKey(a.Init), a.Image, a.Digest, a.Platform}
	kb := []string{b.Name, boolKey(b.Init), b.Image, b.Digest, b.Platform}
	for i := range ka {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return false
}

func boolKey(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// smaller is the lexicographically smaller of two non-empty strings.
func smaller(a, b string) string {
	if a == "" || (b != "" && b < a) {
		return b
	}
	return a
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
