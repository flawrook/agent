#!/bin/sh
# Copyright 2026 Binerals Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Checks the Helm chart (the release gate's "chart" step). Docker only: Helm 3 from a pinned image lints the chart
# and renders it with each value set in test/chart/, and kubeconform from a pinned image checks every rendered
# object against the Kubernetes schemas of the oldest and the newest version the chart is checked on. The checks
# below hold the chart to what it promises (cluster draft 2's "The chart"): kube-system and the lists and watches
# of pods and nodes, and nothing else; the hardened pod; the capped scratch space on disk; the token from a Secret;
# credentials mounted read-only; the final setting names; and a schema that refuses a misspelt or missing value.
# It also renders the largeImages preset, given after the user's file as the README says, and checks that the
# README prints the preset exactly as the chart ships it.
#   test/chart-test.sh [dir]     renders into dir (default dist/chart-test)
# HELM=helm runs a local Helm instead of the image, and KUBECONFORM=skip skips the schema check (test/mutants.py
# sets it); with both, nothing runs in Docker.
set -u
export LC_ALL=C
cd "$(dirname "$0")/.." || exit 1
HELM_IMAGE=alpine/helm:3.22.1@sha256:8191701ad1f82ee3695c87211fcbfe6d7b1bb7df92ac1c8de9ccdb0995a6a2c1
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e
KUBE_VERSIONS="1.25.0 1.37.0" # Chart.yaml's kubeVersion floor, and the version the spike's cluster ran
CHART=deploy/helm/flawrook-agent
SETS="minimal existing-secret everything rbac-off"
PRESET=$CHART/presets/large-images.yaml
mkdir -p "${1:-dist/chart-test}" && OUT=$(cd "${1:-dist/chart-test}" && pwd) || exit 1
checks=0
fails=0

helm() {
  if [ -n "${HELM:-}" ]; then
    command "$HELM" "$@" # command: with HELM=helm, the name is this function's too
  else
    docker run --rm --label org.flawrook.agent=build --memory 256m -v "$PWD":/src:ro -w /src "$HELM_IMAGE" "$@"
  fi
}
ok() { checks=$((checks + 1)); echo "  ok $1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); echo "  FAIL $1"; }
check() { # description, then a command that must succeed
  d=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
# The first rendered object of a kind, from a rendered file.
object() {
  awk -v kind="kind: $2" '
    /^---/ { if (found) exit; doc = ""; next }
    { doc = doc $0 "\n" }
    $0 == kind { found = 1 }
    END { if (found) printf "%s", doc }' "$OUT/$1.yaml"
}
has() { object "$1" "$2" | grep -qxF -- "$3"; }        # set, kind, an exact line
lacks() { ! object "$1" "$2" | grep -qE -- "$3"; }     # set, kind, a pattern no line may match
# The lines that start at an exact line, as many as given, joined by "|": set, kind, first line, count.
block() { object "$1" "$2" | grep -A"$(($4 - 1))" -xF -- "$3" | head -n "$4" | paste -sd'|' -; }
block_is() { [ "$(block "$1" "$2" "$3" "$4")" = "$5" ]; }
env_is() { block_is "$1" Deployment "            - name: $2" 2 "            - name: $2|              value: $3"; }
kinds() { grep '^kind: ' "$OUT/$1.yaml" | sed 's/^kind: //' | sort | paste -sd' ' -; }
refused() { # description, a word the schema's message must hold, then helm's value arguments
  d=$1 want=$2
  shift 2
  if err=$(helm template flawrook-agent "$CHART" "$@" 2>&1 >/dev/null); then
    bad "refused: $d (it rendered)"
  elif printf '%s\n' "$err" | grep -qF schema && printf '%s\n' "$err" | grep -qF -- "$want"; then
    ok "refused: $d"
  else
    bad "refused: $d, but: $(printf '%s' "$err" | tr '\n' ' ')"
  fi
}

echo "helm $(helm version --short 2>/dev/null)"
for set in $SETS; do
  check "$set: lints" helm lint --strict "$CHART" --values "test/chart/$set.yaml"
  if helm template flawrook-agent "$CHART" --namespace flawrook --values "test/chart/$set.yaml" >"$OUT/$set.yaml" 2>"$OUT/$set.err"; then
    ok "$set: renders"
  else
    bad "$set: renders: $(tr '\n' ' ' <"$OUT/$set.err")"
  fi
done

echo "read-only: kube-system, and the lists and watches of pods and nodes; nothing else"
check "the objects" [ "$(kinds minimal)" = "ClusterRole ClusterRoleBinding Deployment Secret ServiceAccount" ]
check "the ClusterRole's rules, exactly" [ "$(object minimal ClusterRole | sed -n '/^rules:/,/^$/p' | sed '/^$/d' | paste -sd'|' -)" = 'rules:|  - apiGroups: [""]|    resources: ["namespaces"]|    resourceNames: ["kube-system"]|    verbs: ["get"]|  - apiGroups: [""]|    resources: ["pods", "nodes"]|    verbs: ["list", "watch"]' ]
check "bound to the agent's ServiceAccount" block_is minimal ClusterRoleBinding "subjects:" 4 "subjects:|  - kind: ServiceAccount|    name: flawrook-agent|    namespace: flawrook"
check "rbac.create=false: no RBAC, no ServiceAccount" [ "$(kinds rbac-off)" = "Deployment Secret" ]
check "rbac.create=false: the given ServiceAccount" has rbac-off Deployment "      serviceAccountName: acme-flawrook"

echo "the hardened pod, with every value set"
for set in $SETS; do
  check "$set: one replica, replaced not rolled" block_is "$set" Deployment "  replicas: 1" 3 "  replicas: 1|  strategy:|    type: Recreate"
  check "$set: non-root 65532" block_is "$set" Deployment "      securityContext:" 4 "      securityContext:|        runAsGroup: 65532|        runAsNonRoot: true|        runAsUser: 65532"
  check "$set: seccomp RuntimeDefault" block_is "$set" Deployment "        seccompProfile:" 2 "        seccompProfile:|          type: RuntimeDefault"
  check "$set: no privilege escalation, every capability dropped, read-only root" block_is "$set" Deployment "          securityContext:" 6 \
    "          securityContext:|            allowPrivilegeEscalation: false|            capabilities:|              drop:|              - ALL|            readOnlyRootFilesystem: true"
  check "$set: no host namespace, path or privilege" lacks "$set" Deployment 'host(Network|PID|IPC|Path|Users)|privileged|add:'
  check "$set: TMPDIR on the scratch emptyDir" env_is "$set" TMPDIR /scratch
  check "$set: the scratch mount" block_is "$set" Deployment "            - name: scratch" 2 "            - name: scratch|              mountPath: /scratch"
  check "$set: the API token mounted" has "$set" Deployment "      automountServiceAccountToken: true"
  check "$set: no probes" lacks "$set" Deployment 'Probe:'
  check "$set: the log as the termination message on an error" has "$set" Deployment "          terminationMessagePolicy: FallbackToLogsOnError"
  check "$set: cluster mode" env_is "$set" FLAWROOK_MODE cluster
done
check "the scratch cap, 2Gi by default" block_is minimal Deployment "        - name: scratch" 3 "        - name: scratch|          emptyDir:|            sizeLimit: 2Gi"
check "the scratch cap, as set" block_is everything Deployment "        - name: scratch" 3 "        - name: scratch|          emptyDir:|            sizeLimit: 4Gi"
check "the scratch on disk, not in memory" lacks everything Deployment 'medium'

echo "the token, from a Secret the kubelet resolves"
check "the chart's own Secret" has minimal Secret "  token: \"$(printf flra_chart0test0token | base64)\""
check "the token from it" block_is minimal Deployment "            - name: FLAWROOK_TOKEN" 5 \
  "            - name: FLAWROOK_TOKEN|              valueFrom:|                secretKeyRef:|                  name: flawrook-agent|                  key: token"
check "existingSecret: no Secret of the chart's" [ "$(kinds existing-secret)" = "ClusterRole ClusterRoleBinding Deployment ServiceAccount" ]
check "existingSecret: the token from it, by its key" block_is existing-secret Deployment "            - name: FLAWROOK_TOKEN" 5 \
  "            - name: FLAWROOK_TOKEN|              valueFrom:|                secretKeyRef:|                  name: flawrook-token|                  key: agent-token"
check "a new token rolls the pod" has minimal Deployment "        checksum/token: $(printf flra_chart0test0token | shasum -a 256 | cut -d' ' -f1)"
check "existingSecret: no checksum (restarted by hand)" lacks existing-secret Deployment 'checksum/'
check "the address" env_is minimal FLAWROOK_URL '"https://flawrook.acme.io"'
check "the address by default" env_is rbac-off FLAWROOK_URL '"https://flawrook.dev"'

echo "GOMEMLIMIT: the agent derives it from the memory limit"
check "not set by the chart" lacks everything Deployment 'name: GOMEMLIMIT'
check "the memory limit it derives it from" block_is minimal Deployment "            limits:" 3 "            limits:|              cpu: 250m|              memory: 1Gi"

echo "the image"
check "by tag: the chart's appVersion" has minimal Deployment '          image: "ghcr.io/flawrook/agent:0.0.0"'
check "by tag and digest, when a digest is given" has everything Deployment '          image: "registry.acme.io/mirror/flawrook-agent:0.0.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'

echo "registry credentials, CA bundle and proxy: read-only files and the environment"
check "none of them unless set" lacks minimal Deployment 'DOCKER_CONFIG|HTTPS_PROXY|NO_PROXY|FLAWROOK_CA_FILE|/etc/flawrook'
check "DOCKER_CONFIG" env_is everything DOCKER_CONFIG /etc/flawrook/registry
check "the registry Secret mounted read-only" block_is everything Deployment "            - name: registry" 3 "            - name: registry|              mountPath: /etc/flawrook/registry|              readOnly: true"
check "as config.json" block_is everything Deployment "        - name: registry" 6 \
  "        - name: registry|          secret:|            secretName: acme-registry|            items:|              - key: .dockerconfigjson|                path: config.json"
check "FLAWROOK_CA_FILE" env_is everything FLAWROOK_CA_FILE /etc/flawrook/ca/acme-root.pem
check "the CA ConfigMap mounted read-only" block_is everything Deployment "            - name: ca" 3 "            - name: ca|              mountPath: /etc/flawrook/ca|              readOnly: true"
check "HTTPS_PROXY" env_is everything HTTPS_PROXY '"http://proxy.acme.io:3128"'
check "NO_PROXY: the cluster's own names first" env_is everything NO_PROXY '"kubernetes.default.svc,.svc,.cluster.local,registry.acme.io,10.0.0.0/8"'

echo "the cluster settings, by their final names"
check "defaults" [ "$(object minimal Deployment | grep -cE 'name: FLAWROOK_(CLUSTER_NAME|INTERVAL|NAMESPACES_|SBOM_)')" -eq 3 ]
check "interval" env_is minimal FLAWROOK_INTERVAL '"60m"'
check "cluster name" env_is everything FLAWROOK_CLUSTER_NAME '"prod-eu-1"'
check "namespaces included" env_is everything FLAWROOK_NAMESPACES_INCLUDE '"shop,data"'
check "namespaces excluded" env_is everything FLAWROOK_NAMESPACES_EXCLUDE '"kube-system"'
check "the image size cap, in bytes" env_is everything FLAWROOK_SBOM_MAX_IMAGE_BYTES '"536870912"'
check "concurrency" env_is everything FLAWROOK_SBOM_CONCURRENCY '"2"'
check "scheduling values" has everything Deployment "      priorityClassName: acme-low"
check "ServiceAccount annotations" has everything ServiceAccount "    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/flawrook-agent"

echo "sizing: the 300 MiB default, and the largeImages preset as a second --values"
check "the image size cap, 300 MiB by default" env_is minimal FLAWROOK_SBOM_MAX_IMAGE_BYTES '"314572800"'
check "large-images: lints" helm lint --strict "$CHART" --values test/chart/minimal.yaml --values "$PRESET"
for set in large-images after-preset; do
  case $set in
  large-images) values="--values test/chart/minimal.yaml --values $PRESET" ;;
  *) values="--values test/chart/minimal.yaml --values $PRESET --values test/chart/after-preset.yaml" ;;
  esac
  # shellcheck disable=SC2086 # one argument per word of $values
  if helm template flawrook-agent "$CHART" --namespace flawrook $values >"$OUT/$set.yaml" 2>"$OUT/$set.err"; then
    ok "$set: renders"
  else
    bad "$set: renders: $(tr '\n' ' ' <"$OUT/$set.err")"
  fi
done
check "large-images: the cap, 1 GiB" env_is large-images FLAWROOK_SBOM_MAX_IMAGE_BYTES '"1073741824"'
check "large-images: 4Gi of memory, cpu unchanged" block_is large-images Deployment "            limits:" 3 "            limits:|              cpu: 250m|              memory: 4Gi"
check "large-images: the requests unchanged" block_is large-images Deployment "            requests:" 3 "            requests:|              cpu: 50m|              memory: 128Mi"
check "large-images: 6Gi of scratch" block_is large-images Deployment "        - name: scratch" 3 "        - name: scratch|          emptyDir:|            sizeLimit: 6Gi"
check "a file after the preset wins" block_is after-preset Deployment "            limits:" 3 "            limits:|              cpu: 250m|              memory: 8Gi"
check "a file after the preset: the preset's other keys stay" env_is after-preset FLAWROOK_SBOM_MAX_IMAGE_BYTES '"1073741824"'
check "a file after the preset: the preset's scratch stays" block_is after-preset Deployment "        - name: scratch" 3 "        - name: scratch|          emptyDir:|            sizeLimit: 6Gi"
# The README's copy of the preset: the yaml block whose first line is the preset's.
readme_preset() {
  awk -v first="$(head -n 1 "$PRESET")" '
    copy && $0 == "```" { exit }
    copy { print; next }
    prev == "```yaml" && $0 == first { copy = 1; print }
    { prev = $0 }' "$CHART/README.md"
}
check "the README prints the preset as the chart ships it" [ "$(readme_preset)" = "$(cat "$PRESET")" ]

echo "the schema refuses"
refused "no token" token --set flawrook.url=https://flawrook.acme.io
refused "a token and an existingSecret" existingSecret --values test/chart/minimal.yaml --set flawrook.existingSecret=flawrook-token
refused "a misspelt key" resource --values test/chart/minimal.yaml --set resource.limits.memory=1Gi
refused "a misspelt nested key" httpProxy --values test/chart/minimal.yaml --set proxy.httpProxy=http://proxy.acme.io:3128
refused "plain http" url --values test/chart/minimal.yaml --set flawrook.url=http://flawrook.acme.io
refused "a token that isn't an agent token" token --values test/chart/minimal.yaml --set flawrook.token=ghp_0123456789 # gitleaks:allow (made up)
refused "no memory limit" memory --values test/chart/minimal.yaml --set resources.limits.memory=null
refused "more than 4 builds at once" concurrency --values test/chart/minimal.yaml --set sbom.concurrency=5
refused "a malformed digest" digest --values test/chart/minimal.yaml --set image.digest=sha256:0123

if [ "${KUBECONFORM:-}" = skip ]; then
  echo "kubeconform: skipped (KUBECONFORM=skip)"
else
  echo "kubeconform -strict, every rendered object"
  for v in $KUBE_VERSIONS; do
    # shellcheck disable=SC2046 # one argument per rendered file
    if docker run --rm --label org.flawrook.agent=build --memory 256m -v "$OUT":/rendered:ro "$KUBECONFORM_IMAGE" \
      -strict -summary -kubernetes-version "$v" $(for set in $SETS large-images; do echo "/rendered/$set.yaml"; done) >"$OUT/kubeconform-$v.txt" 2>&1; then
      ok "Kubernetes $v: $(tail -1 "$OUT/kubeconform-$v.txt")"
    else
      bad "Kubernetes $v: $(tr '\n' ' ' <"$OUT/kubeconform-$v.txt")"
    fi
  done
fi

echo "chart: $checks checks, $fails failed"
[ "$fails" -eq 0 ]
