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

// The fields of the API's objects that cluster mode reads, and no others: decoding into these keeps a large
// cluster's lists small in memory.

type ObjectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	GenerateName    string            `json:"generateName"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []OwnerReference  `json:"ownerReferences"`
}

type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

type PodSpec struct {
	NodeName       string          `json:"nodeName"`
	Containers     []ContainerSpec `json:"containers"`
	InitContainers []ContainerSpec `json:"initContainers"`
}

type ContainerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type PodStatus struct {
	Phase                 string            `json:"phase"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses"`
}

// ContainerStatus: Image is the reference as the runtime resolved it, ImageID the running image's digest
// ("repo@sha256:…"), empty while the container waits.
type ContainerStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
}

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		ProviderID string `json:"providerID"`
	} `json:"spec"`
	Status struct {
		NodeInfo NodeInfo `json:"nodeInfo"`
	} `json:"status"`
}

type NodeInfo struct {
	KubeletVersion          string `json:"kubeletVersion"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
	OSImage                 string `json:"osImage"`
	KernelVersion           string `json:"kernelVersion"`
	Architecture            string `json:"architecture"`
	OperatingSystem         string `json:"operatingSystem"`
}

// Namespace is kube-system: its UID is the cluster's identity.
type Namespace struct {
	Metadata ObjectMeta `json:"metadata"`
}

// Version is /version.
type Version struct {
	GitVersion string `json:"gitVersion"`
}
