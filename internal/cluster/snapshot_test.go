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
	"encoding/json"
	"strings"
	"testing"

	"flawrook.dev/agent/internal/kube"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func owned(kind, name string, controller bool) kube.ObjectMeta {
	c := controller
	return kube.ObjectMeta{OwnerReferences: []kube.OwnerReference{{Kind: kind, Name: name, Controller: &c}}}
}

func TestOwner(t *testing.T) {
	withLabels := func(m kube.ObjectMeta, name string, labels map[string]string) kube.Pod {
		m.Name, m.Labels = name, labels
		return kube.Pod{Metadata: m}
	}
	cases := []struct {
		pod        kube.Pod
		kind, name string
	}{
		{withLabels(owned("ReplicaSet", "web-6db9777684", true), "web-6db9777684-tbfsn", map[string]string{"pod-template-hash": "6db9777684"}), "Deployment", "web"},
		// The suffix must be the pod's own hash label, else it's a ReplicaSet as written.
		{withLabels(owned("ReplicaSet", "web-6db9777684", true), "x", map[string]string{"pod-template-hash": "other"}), "ReplicaSet", "web-6db9777684"},
		{withLabels(owned("ReplicaSet", "web-6db9777684", true), "x", nil), "ReplicaSet", "web-6db9777684"},
		{withLabels(owned("ReplicaSet", "canary-5f7c9d", true), "x", map[string]string{"rollouts-pod-template-hash": "5f7c9d"}), "Rollout", "canary"},
		{withLabels(owned("Job", "backup-29921385", true), "x", nil), "CronJob", "backup"},
		{withLabels(owned("Job", "nightly-report-1234567", true), "x", nil), "Job", "nightly-report-1234567"},
		{withLabels(owned("Job", "migrate", true), "x", nil), "Job", "migrate"},
		{withLabels(owned("Node", "cp-1", true), "kube-apiserver-cp-1", nil), "StaticPod", "kube-apiserver"},
		{withLabels(owned("StatefulSet", "db", true), "db-0", nil), "StatefulSet", "db"},
		{withLabels(owned("DaemonSet", "fluent", true), "fluent-x7k2p", nil), "DaemonSet", "fluent"},
		{withLabels(owned("Workflow", "etl-8h2k", true), "etl-8h2k-123", nil), "Workflow", "etl-8h2k"},
		// Not a controller: the pod counts as having no owner.
		{withLabels(owned("ReplicaSet", "web-1", false), "bare", nil), "Pod", "bare"},
		{kube.Pod{Metadata: kube.ObjectMeta{Name: "debug-x9z", GenerateName: "debug-"}}, "Pod", "debug"},
		{kube.Pod{Metadata: kube.ObjectMeta{Name: "lonely"}}, "Pod", "lonely"},
	}
	for _, tc := range cases {
		if kind, name := Owner(tc.pod); kind != tc.kind || name != tc.name {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.pod.Metadata.Name, kind, name, tc.kind, tc.name)
		}
	}
}

func TestParseImageID(t *testing.T) {
	cases := []struct {
		in, repo, digest string
		ok               bool
	}{
		{"docker.io/library/nginx@" + dA, "docker.io/library/nginx", dA, true},
		{"docker-pullable://nginx@" + dA, "nginx", dA, true},
		{"docker://" + dB, "", dB, true},
		{dB, "", dB, true},
		{"localhost:5000/team/app@" + dC, "localhost:5000/team/app", dC, true},
		{"", "", "", false},
		{"nginx:1.27", "", "", false},
		{"nginx@sha256:short", "", "", false},
		{"nginx@SHA256:" + strings.Repeat("A", 64), "", "", false},
	}
	for _, tc := range cases {
		repo, digest, ok := ParseImageID(tc.in)
		if repo != tc.repo || digest != tc.digest || ok != tc.ok {
			t.Errorf("%q: got %q %q %v", tc.in, repo, digest, ok)
		}
	}
}

func node(name, arch string) kube.Node {
	n := kube.Node{Metadata: kube.ObjectMeta{Name: name}}
	n.Spec.ProviderID = "aws:///eu-west-1a/i-0abc"
	n.Status.NodeInfo = kube.NodeInfo{KubeletVersion: "v1.37.0", ContainerRuntimeVersion: "containerd://2.3.4", OSImage: "Debian GNU/Linux 13 (trixie)",
		KernelVersion: "6.12.54", Architecture: arch, OperatingSystem: "linux"}
	return n
}

// pod: a Deployment's pod on a node, one container per image id, the spec image as written.
func pod(ns, name, nodeName, rs, hash string, containers ...[3]string) kube.Pod {
	p := kube.Pod{Metadata: owned("ReplicaSet", rs+"-"+hash, true)}
	p.Metadata.Namespace, p.Metadata.Name, p.Metadata.Labels = ns, name, map[string]string{"pod-template-hash": hash}
	p.Spec.NodeName = nodeName
	for _, c := range containers { // name, spec image, imageID
		p.Spec.Containers = append(p.Spec.Containers, kube.ContainerSpec{Name: c[0], Image: c[1]})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, kube.ContainerStatus{Name: c[0], Image: "docker.io/library/" + c[1], ImageID: c[2]})
	}
	return p
}

func TestBuild(t *testing.T) {
	nodes := []kube.Node{node("w2", "arm64"), node("w1", "arm64")}
	web1 := pod("shop", "web-1", "w1", "web", "h1", [3]string{"nginx", "nginx:1.27", "docker.io/library/nginx@" + dA})
	web2 := pod("shop", "web-2", "w2", "web", "h1", [3]string{"nginx", "nginx:1.27", "mirror.acme.io/library/nginx@" + dA})
	// The same digest under another runtime ref and repository: the smallest of each wins, whatever the pod order.
	web2.Status.ContainerStatuses[0].Image = "mirror.acme.io/library/nginx:1.27"
	// An init container, and a container still waiting (no imageID): the waiting one is left out.
	job := kube.Pod{Metadata: owned("Job", "backup-29921385", true)}
	job.Metadata.Namespace, job.Metadata.Name, job.Spec.NodeName = "ops", "backup-29921385-x", "w1"
	job.Spec.InitContainers = []kube.ContainerSpec{{Name: "fetch", Image: "alpine:3.20"}}
	job.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "fetch", Image: "docker.io/library/alpine:3.20", ImageID: "docker.io/library/alpine@" + dB}}
	job.Spec.Containers = []kube.ContainerSpec{{Name: "run", Image: "busybox"}}
	job.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "run", Image: "busybox"}}
	job.Status.Phase = "Succeeded" // finished pods count while they exist
	preloaded := pod("kube-system", "coredns-1", "w1", "coredns", "h9", [3]string{"coredns", "registry.k8s.io/coredns:v1.12", "docker.io/library/import-2026-08-26@" + dC})
	unscheduled := pod("shop", "web-3", "", "web", "h1", [3]string{"nginx", "nginx:1.27", "docker.io/library/nginx@" + dC})
	excluded := pod("kube-node-lease", "x", "w1", "x", "h2", [3]string{"x", "x:1", "docker.io/library/x@" + dC})

	snap := Build([]kube.Pod{web1, web2, job, preloaded, unscheduled, excluded}, nodes, Scope{Exclude: []string{"kube-node-lease"}},
		map[ImageKey]Status{{dA, "linux/arm64"}: {Status: Error, Reason: "pull-failed", Detail: "x"}})

	if len(snap.Nodes) != 2 || snap.Nodes[0].Name != "w1" || *snap.Nodes[0].Provider != "aws" {
		t.Fatalf("nodes %+v", snap.Nodes)
	}
	got := map[string]Workload{}
	for _, w := range snap.Workloads {
		got[w.Namespace+"/"+w.Kind+"/"+w.Name] = w
	}
	if len(got) != 3 {
		t.Fatalf("workloads %+v", snap.Workloads)
	}
	// Two pods of one Deployment on two nodes, same image: one row.
	if w := got["shop/Deployment/web"]; len(w.Containers) != 1 || w.Containers[0] != (Container{Name: "nginx", Image: "nginx:1.27", Digest: dA, Platform: "linux/arm64"}) {
		t.Fatalf("web %+v", w)
	}
	if w := got["ops/CronJob/backup"]; len(w.Containers) != 1 || !w.Containers[0].Init || w.Containers[0].Name != "fetch" {
		t.Fatalf("cronjob %+v", w)
	}
	if len(snap.Images) != 3 {
		t.Fatalf("images %+v", snap.Images)
	}
	byDigest := map[string]Image{}
	for _, img := range snap.Images {
		byDigest[img.Digest] = img
	}
	if img := byDigest[dA]; img.Repo != "docker.io/library/nginx" || img.Ref != "docker.io/library/nginx:1.27" || img.Reason != "pull-failed" {
		t.Fatalf("nginx %+v", img)
	}
	if img := byDigest[dB]; !img.Scannable() {
		t.Fatalf("alpine %+v", img)
	}
	// An import name is classified before any request, whatever the statuses say.
	if img := byDigest[dC]; img.Status.Status != NotPullable || img.Reason != "no-registry-digest" {
		t.Fatalf("preloaded %+v", img)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		img            Image
		status, reason string
	}{
		{Image{ImageKey: ImageKey{dA, "linux/amd64"}, Repo: ""}, NotPullable, "no-registry-digest"},
		{Image{ImageKey: ImageKey{dA, "linux/amd64"}, Repo: "import-2026-11-20"}, NotPullable, "no-registry-digest"},
		{Image{ImageKey: ImageKey{dA, "linux/amd64"}, Repo: "docker.io/library/import-2026-08-26"}, NotPullable, "no-registry-digest"},
		{Image{ImageKey: ImageKey{dA, "windows/amd64"}, Repo: "mcr.microsoft.com/windows/servercore"}, Error, "unsupported-platform"},
		{Image{ImageKey: ImageKey{dA, "linux/amd64"}, Repo: "docker.io/library/important-2026"}, "", ""},
		{Image{ImageKey: ImageKey{dA, "linux/amd64"}, Repo: "ghcr.io/acme/import-2026-08-26"}, "", ""},
	}
	for _, tc := range cases {
		if s := Classify(tc.img); s.Status != tc.status || s.Reason != tc.reason {
			t.Errorf("%+v: got %+v", tc.img, s)
		}
	}
}

func TestScope(t *testing.T) {
	if !(Scope{}).covers("any") || (Scope{Include: []string{"a"}}).covers("b") || !(Scope{Include: []string{"a"}}).covers("a") ||
		(Scope{Exclude: []string{"a"}}).covers("a") || (Scope{Include: []string{"a"}, Exclude: []string{"a"}}).covers("a") {
		t.Fatal("scope")
	}
}

func hashOf(pods []kube.Pod, nodes []kube.Node, statuses map[ImageKey]Status) string {
	name := "prod"
	return NewReport(Agent{Version: "0.3.0", Mode: Mode}, Info{ID: strings.Repeat("9", 64), Name: &name}, Build(pods, nodes, Scope{}, statuses)).ReportHash
}

func TestHashIsControllerLevel(t *testing.T) {
	nodes := []kube.Node{node("w1", "arm64")}
	web := func(name, nodeName, hash, imageID string) kube.Pod {
		return pod("shop", name, nodeName, "web", hash, [3]string{"nginx", "nginx:1.27", imageID})
	}
	base := hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, nodes, nil)

	same := map[string]string{
		"another replica":            hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA), web("web-2", "w1", "h1", "nginx@"+dA)}, nodes, nil),
		"a rescheduled pod":          hashOf([]kube.Pod{web("web-9", "w2", "h1", "nginx@"+dA)}, []kube.Node{node("w2", "arm64")}, nil),
		"a node added, same facts":   hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, []kube.Node{node("w1", "arm64"), node("w3", "arm64")}, nil),
		"a status detail changed":    hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, nodes, map[ImageKey]Status{}),
		"pods listed in other order": hashOf([]kube.Pod{web("b", "w1", "h1", "nginx@"+dA), web("a", "w1", "h1", "nginx@"+dA)}, nodes, nil),
	}
	for what, h := range same {
		if h != base {
			t.Errorf("%s changed the hash", what)
		}
	}
	withDetail := func(d string) string {
		return hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, nodes, map[ImageKey]Status{{dA, "linux/arm64"}: {Status: Error, Reason: "pull-failed", Detail: d}})
	}
	if withDetail("one") != withDetail("two") {
		t.Error("detail changed the hash")
	}

	upgraded := node("w1", "arm64")
	upgraded.Status.NodeInfo.KubeletVersion = "v1.37.1"
	differs := map[string]string{
		"a new digest":         hashOf([]kube.Pod{web("web-1", "w1", "h2", "nginx@"+dB)}, nodes, nil),
		"a node upgrade":       hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, []kube.Node{upgraded}, nil),
		"a status":             withDetail("one"),
		"a new workload":       hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA), pod("shop", "api-1", "w1", "api", "h3", [3]string{"api", "api:1", "api@" + dC})}, nodes, nil),
		"another architecture": hashOf([]kube.Pod{web("web-1", "w1", "h1", "nginx@"+dA)}, []kube.Node{node("w1", "amd64")}, nil),
	}
	for what, h := range differs {
		if h == base {
			t.Errorf("%s didn't change the hash", what)
		}
	}
	// A re-tag with the same digest is a change of spec.
	retag := pod("shop", "web-1", "w1", "web", "h1", [3]string{"nginx", "nginx:stable", "nginx@" + dA})
	if hashOf([]kube.Pod{retag}, nodes, nil) == base {
		t.Error("a re-tag didn't change the hash")
	}
}

func TestReportJSONShape(t *testing.T) {
	r := NewReport(Agent{Version: "0.3.0", OS: "linux", Arch: "arm64", Mode: Mode}, Info{ID: strings.Repeat("9", 64)}, Snapshot{})
	raw, _ := json.Marshal(r)
	for _, want := range []string{`"mode":"cluster"`, `"name":null`, `"version":null`, `"scope":{"include":[],"exclude":[]}`,
		`"nodes":[]`, `"workloads":[]`, `"images":[]`, `"reportHash":"sha256:`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s lacks %s", raw, want)
		}
	}
	img, _ := json.Marshal(Image{ImageKey: ImageKey{dA, "linux/arm64"}, Ref: "r", Repo: "hidden"})
	if string(img) != `{"digest":"`+dA+`","platform":"linux/arm64","ref":"r"}` {
		t.Errorf("a scannable image: %s", img)
	}
}
