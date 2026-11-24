# FlawRook agent for Kubernetes

This Helm chart runs the FlawRook agent in cluster mode: one pod that reports a cluster's nodes, its workloads and
the images they run to FlawRook. For a Linux server, use the agent's install line instead (see the agent's
[README](https://github.com/flawrook/agent#install)).

## What it does in your cluster

- It reads one namespace, `kube-system`, whose id identifies the cluster, and lists and watches pods and nodes,
  cluster-wide. Nothing else: it never reads a Secret, a ConfigMap, another namespace or a pod's logs, never runs a
  command in a pod, and creates or changes nothing.
- It asks FlawRook which of the running images it has no SBOM for yet. An image FlawRook already has, from another
  cluster in your workspace too, isn't pulled again.
- Each of those it pulls from its registry, for the node's platform, into a scratch volume on the node's disk
  (`scratch.sizeLimit`, 2Gi by default). It lists the image's packages and deletes the layers. One image at a time
  by default.
- It sends what it found to your FlawRook address over HTTPS. It opens no port and has no Service.
- It runs as one pod: user 65532, a read-only root file system, no capabilities, no privilege escalation, seccomp
  `RuntimeDefault`. The pod meets the "restricted" Pod Security Standard. It sets its Go memory limit to 75% of the
  pod's memory limit.
- The token reaches the pod from a Secret, which the kubelet resolves when the pod starts. Registry credentials and
  a CA bundle are mounted as read-only files.
- An image it can't pull or read shows in FlawRook as not scanned, with the reason, never as clean.

## Before you install

- An agent token (`flra_…`): FlawRook, Integrations, Agents.
- Kubernetes 1.25 or newer, k3s and RKE2 included. OpenShift isn't supported yet. The chart is tested with Helm 3.22
  and 4.2.
- cosign 2 or newer, to check the signatures.
- Egress from the agent's namespace:
  - the Kubernetes API server;
  - your FlawRook address, on 443;
  - every registry your cluster's images come from, on 443.

  A proxy can carry the last two (see Proxy and private CA).

## Check the signatures

The chart and the image are signed with the same cosign key as the agent's releases. The public key is
`packaging/cosign.pub` in the agent's repository.

```sh
VERSION=<version>   # the agent release, without the v
curl -fsSLO "https://raw.githubusercontent.com/flawrook/agent/v$VERSION/packaging/cosign.pub"
cosign verify --key cosign.pub --insecure-ignore-tlog=true "ghcr.io/flawrook/charts/flawrook-agent:$VERSION"
```

- cosign prints the checked chart's digest as `docker-manifest-digest`. Install by that digest, so that what you
  install is exactly what you checked.
- The chart pins the agent's image by its digest. Check the image too:

  ```sh
  CHART=oci://ghcr.io/flawrook/charts/flawrook-agent@sha256:<the chart's digest>
  helm show values "$CHART" | grep 'digest:'
  cosign verify --key cosign.pub --insecure-ignore-tlog=true ghcr.io/flawrook/agent@sha256:<the image's digest>
  ```

- The signatures aren't in a public transparency log, so cosign checks them against the key alone.
  `--insecure-ignore-tlog=true` says so, and cosign warns about it.

## Install

1. Give the agent a namespace of its own. Label it before the pod starts, so the cluster enforces the
   restricted profile:

   ```sh
   kubectl create namespace flawrook
   kubectl label namespace flawrook pod-security.kubernetes.io/enforce=restricted
   ```

2. Keep the token in a Secret of your own. Then the token isn't in Helm's values or in its release history:

   ```sh
   read -rs FLAWROOK_TOKEN   # paste the token; it isn't shown or kept in the shell's history
   printf %s "$FLAWROOK_TOKEN" | kubectl -n flawrook create secret generic flawrook-token --from-file=token=/dev/stdin
   unset FLAWROOK_TOKEN
   ```

3. Write the values to a file, `flawrook-values.yaml`:

   ```yaml
   flawrook:
     url: https://<your FlawRook address>   # https://flawrook.dev by default
     existingSecret: flawrook-token
   clusterName: <the name to show in FlawRook>
   ```

   Set `clusterName`: two clusters reported under the same name are told apart in FlawRook only by their ids.

4. Install the chart, by the digest you checked:

   ```sh
   helm install flawrook-agent "$CHART" --namespace flawrook --values flawrook-values.yaml
   kubectl -n flawrook rollout status deploy/flawrook-agent
   kubectl -n flawrook logs deploy/flawrook-agent
   ```

The cluster appears in FlawRook under **Servers and clusters** after its first report.

To see exactly what the agent may do:

```sh
kubectl auth can-i --list --as=system:serviceaccount:flawrook:flawrook-agent
```

The list shows get on the namespace `kube-system`, and list and watch on pods and nodes. The rest are the defaults
Kubernetes gives every signed-in identity, such as asking what it may do.

Install it once per cluster: a second agent reports the same cluster again.

If the agent can't read `kube-system`, it stops at once, and the pod shows `CrashLoopBackOff`; its log says why.
When it stops on an error, `kubectl describe pod` shows the end of its log. It has no probes, since it has no
listener: an agent that hangs shows as stale in FlawRook after 24 hours.

## Values

A misspelt key, or a value of the wrong kind, stops `helm install` with the schema's message.

| Key | Default | Meaning |
|---|---|---|
| `flawrook.url` | `https://flawrook.dev` | Your FlawRook address, https |
| `flawrook.existingSecret` | | Your Secret with the token |
| `flawrook.existingSecretKey` | `token` | The token's key in it |
| `flawrook.token` | | The token itself, instead of `existingSecret`. The chart keeps it in a Secret, and Helm keeps it in the release's history |
| `clusterName` | | The cluster's name in FlawRook |
| `interval` | `60m` | How often the agent reports, or sends a heartbeat when nothing changed: 10m to 24h. A change in the cluster is reported after a minute of quiet, at most every 5 minutes |
| `namespaces.include`, `namespaces.exclude` | all, none | The namespaces whose workloads are reported, by exact name |
| `sbom.maxImageBytes` | 300 MiB | An image larger than this, compressed, is reported as too large and never pulled. See Sizing |
| `sbom.concurrency` | 1 | Images pulled at once, 1 to 4; each takes its room in the scratch volume |
| `scratch.sizeLimit` | `2Gi` | The scratch volume's cap, on the node's disk. The kubelet evicts the pod if it grows past this |
| `resources` | requests 50m, 128Mi; limits 250m, 1Gi | `limits.memory` must be set: the agent's Go memory limit is 75% of it |
| `proxy.httpsProxy`, `proxy.noProxy` | | See Proxy and private CA |
| `caBundle.configMap` | | See Proxy and private CA |
| `caBundle.key` | `ca.crt` | The bundle's key in that ConfigMap |
| `registryCredentials.existingSecret` | | See Private registries |
| `image.repository`, `image.tag`, `image.digest`, `image.pullPolicy` | the release's image, by tag and digest | To pull the image from your own mirror |
| `serviceAccount.create`, `.name`, `.annotations` | `true` | The agent's ServiceAccount |
| `rbac.create` | `true` | `false`: bind the read rules yourself (pods, nodes, namespaces: get, list, watch) |
| `podSecurityContext`, `securityContext` | hardened, see above | |
| `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | Where the pod runs |

## Sizing

The defaults build images up to 300 MiB compressed. The agent pulls each image into the scratch volume and reads
it in memory, so the cap, the memory limit and the scratch size go together.

**What a build takes**, measured on one k3s VM (amd64), 2026-11-23:

- memory is 3 to 4 times the image's compressed size, and scratch is about 5 times;
- n8n, 360 MiB compressed and 2,149 packages, took the whole 1 GiB of memory and 1,759 MiB of scratch;
- eclipse-temurin:21-jdk, 220 MiB compressed, took 905 MiB of memory and 704 MiB of scratch.

**Size from the biggest image your cluster runs:**

- `sbom.maxImageBytes`: at least its compressed size;
- `resources.limits.memory`: about 4 times that, and never under 1Gi;
- `scratch.sizeLimit`: about 5 times that, times `sbom.concurrency`.

**Finding the biggest image.** An image over the cap shows on its cluster's page in FlawRook as not scanned,
"larger than the 300 MiB limit". The agent's log gives each image's compressed size as `sizeBytes` on its `built`
line. For any image, add up the sizes of the layers in its manifest for your nodes' platform, for example:

```sh
crane manifest --platform linux/amd64 <image> | jq '[.layers[].size] | add'
```

**Images up to 1 GiB.** The chart ships a preset for them, `presets/large-images.yaml`. Save it as
`large-images.yaml`:

```yaml
# The largeImages preset, for images up to 1 GiB compressed. Give it as a second --values, after your own file.
sbom:
  maxImageBytes: 1073741824
resources:
  limits:
    memory: 4Gi
scratch:
  sizeLimit: 6Gi
```

Give it as a second `--values`, after your own file:

```sh
helm install flawrook-agent "$CHART" --namespace flawrook --values flawrook-values.yaml --values large-images.yaml
```

The preset's three keys override the same keys in your file. To change one of them, add `--set`, or a third file
after the preset. The preset keeps the 128Mi memory request.

**CPU sets the build time.** n8n took 243 s at the 250m CPU limit.

**What the requests reserve.** The pod requests 128Mi of memory, so the scheduler reserves only that. A node needs
the free memory, up to `limits.memory`, while a large image builds.

**The memory in the log.** Each `built` line carries `memBuildMaxMiB`, the highest of the pod's `memory.current`,
read once a second while that image built. With `sbom.concurrency` over 1, it covers every build running at the
same time. `memPeakMiB` is the pod's peak since it started.

## Private registries

Images in a private registry need a pull credential. Give the agent a `kubernetes.io/dockerconfigjson` Secret in
its namespace, best one that can only pull:

```sh
kubectl -n flawrook create secret generic flawrook-registry \
  --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson=<a Docker config.json>
```

Then set `registryCredentials.existingSecret: flawrook-registry`. The kubelet mounts it read-only, and the agent
reads it as a Docker config file.

- The file must hold plain `auths` entries. A `credsStore` or `credHelpers` entry names a helper program the image
  doesn't have, and every pull would fail.
- The agent reads the file again for each pull, so a change to the Secret applies within about a minute, with no
  restart.
- If the file can't be read as a Docker config, the agent logs it once and pulls without credentials. Public images
  are still scanned; private ones show as not scanned, "registry config file can't be read".
- Docker Hub limits anonymous pulls, and each image the agent hasn't seen costs one. If your cluster runs many
  Docker Hub images, add a Docker Hub entry (`https://index.docker.io/v1/`, with a read-only access token) to the
  same file. Docker Hub answers a missing repository as it answers a private one, so FlawRook says that it may be
  either.

## Proxy and private CA

- `proxy.httpsProxy` carries the agent's connections to FlawRook and to the registries. The cluster's own names
  (`kubernetes.default.svc`, `.svc`, `.cluster.local`) are always reached directly. Add your own hosts to
  `proxy.noProxy`, comma-separated.
- If FlawRook is behind a private CA, or the proxy inspects TLS, put the PEM bundle in a ConfigMap in the agent's
  namespace and name it in `caBundle.configMap` (its key in `caBundle.key`). The agent trusts it besides the
  system's.

## Limitations

- **Registry mirrors aren't seen.** The agent pulls from the registry an image's reference names, not through a
  mirror the nodes use (k3s's `registries.yaml`, a pull-through cache, GKE's mirror). Without egress to that
  registry, its images show as not scanned, "registry unreachable".
- **Jobs named with a date.** A Job whose name ends in a dash and 8 or more digits is read as a CronJob's run: a Job
  you made named `backup-20261121` shows as the CronJob `backup`.
- **Runs with their own owners.** Argo Workflows, Tekton TaskRuns and PipelineRuns, and SparkApplications get a new
  owner name for each run, so each run is a change and brings a report, at most one every 5 minutes.
- **A CronJob whose pods are deleted between runs** leaves the report and comes back with each run. With the default
  history, which keeps the last three Jobs' pods, this doesn't happen.
- **OpenShift** isn't supported yet.

## Upgrade

Check the new release's signatures as above, then:

```sh
helm upgrade flawrook-agent oci://ghcr.io/flawrook/charts/flawrook-agent@sha256:<the new chart's digest> \
  --namespace flawrook --values flawrook-values.yaml
```

Any change to the values, the chart's own token included, rolls the pod. The agent reads its token and its
settings when it starts, so after you change a Secret or ConfigMap of your own (`existingSecret`, the CA bundle),
restart it: `kubectl -n flawrook rollout restart deploy/flawrook-agent`. The registry Secret needs no restart.

## Uninstall

```sh
helm uninstall flawrook-agent --namespace flawrook
kubectl delete namespace flawrook
```

- `helm uninstall` deletes everything the chart made: the Deployment and its pod, with the scratch volume, the
  ServiceAccount, the ClusterRole, the ClusterRoleBinding, the chart's own Secret if any, and the release's
  history.
- Deleting the namespace deletes what you made in it: the token's Secret, the registry Secret and the CA ConfigMap.
  If the namespace holds anything else, delete those three by name instead.
- With `rbac.create: false`, delete your own binding as well.
- This prints nothing once it's all gone:

  ```sh
  kubectl get clusterrole,clusterrolebinding -l app.kubernetes.io/instance=flawrook-agent
  ```

- Then, in FlawRook, revoke the token (Integrations, Agents), and remove the cluster in its project's Settings if
  you no longer want its findings.

## For maintainers: the first release

New packages on ghcr.io start private. After the first release that publishes them, an owner of the flawrook
organization makes both public, once: `agent` and `charts/flawrook-agent` (the package's settings, Change
visibility). Later releases keep that visibility.
