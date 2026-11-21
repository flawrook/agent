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

package report

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"flawrook.dev/agent/internal/hostinfo"
)

var agent = Agent{Version: "0.1.0", OS: "linux", Arch: "arm64"}

func host() hostinfo.Info {
	return hostinfo.Info{HostID: strings.Repeat("a", 64), HostIDSource: "machine-id", Hostname: "web-1", Kernel: "6.1.0-47-arm64", OSRelease: map[string]string{"ID": "debian", "VERSION_ID": "12"}}
}

// Two Syft runs over the same host: another serial number and timestamp, the components and their
// properties in another order.
const sbomA = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1111","version":1,
 "metadata":{"timestamp":"2026-11-20T08:00:00Z","tools":{"components":[{"name":"flawrook-agent","version":"0.1.0"}]}},
 "components":[
  {"bom-ref":"a","name":"openssl","version":"3.0.15-1~deb12u1","properties":[{"name":"p1","value":"x"},{"name":"p2","value":"y"}]},
  {"bom-ref":"b","name":"zlib1g","version":"1:1.2.13.dfsg-1"}],
 "dependencies":[{"ref":"a","dependsOn":["b"]}]}`

const sbomB = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:2222","version":1,
 "metadata":{"timestamp":"2026-11-20T09:00:00Z","tools":{"components":[{"name":"flawrook-agent","version":"0.1.0"}]}},
 "components":[
  {"bom-ref":"b","name":"zlib1g","version":"1:1.2.13.dfsg-1"},
  {"bom-ref":"a","name":"openssl","version":"3.0.15-1~deb12u1","properties":[{"name":"p2","value":"y"},{"name":"p1","value":"x"}]}],
 "dependencies":[{"ref":"a","dependsOn":["b"]}]}`

func mustHash(t *testing.T, a Agent, h hostinfo.Info, sbom string) string {
	t.Helper()
	got, err := Hash(a, h, []byte(sbom))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "sha256:") || len(got) != 71 {
		t.Fatalf("hash %q", got)
	}
	return got
}

func TestHashIgnoresSerialTimestampAndOrder(t *testing.T) {
	if a, b := mustHash(t, agent, host(), sbomA), mustHash(t, agent, host(), sbomB); a != b {
		t.Fatalf("the same inventory hashes differently: %s %s", a, b)
	}
}

func TestHashChangesWithTheInventoryKernelOSReleaseHostnameAndVersion(t *testing.T) {
	base := mustHash(t, agent, host(), sbomA)
	changed := map[string]string{}
	changed["a package version"] = mustHash(t, agent, host(), strings.Replace(sbomA, "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", 1))
	changed["a package removed"] = mustHash(t, agent, host(), strings.Replace(sbomA, `,
  {"bom-ref":"b","name":"zlib1g","version":"1:1.2.13.dfsg-1"}`, "", 1))
	k := host()
	k.Kernel = "6.1.0-48-arm64"
	changed["the kernel"] = mustHash(t, agent, k, sbomA)
	o := host()
	o.OSRelease = map[string]string{"ID": "debian", "VERSION_ID": "13"}
	changed["os-release"] = mustHash(t, agent, o, sbomA)
	n := host()
	n.Hostname = "web-2"
	changed["the hostname"] = mustHash(t, agent, n, sbomA)
	v := agent
	v.Version = "0.1.1"
	changed["the agent version"] = mustHash(t, v, host(), sbomA)
	for what, h := range changed {
		if h == base {
			t.Errorf("%s doesn't change the hash", what)
		}
	}
}

func TestHashRejectsAnSBOMThatIsntJSON(t *testing.T) {
	if _, err := Hash(agent, host(), []byte("not json")); err == nil {
		t.Fatal("no error")
	}
}

func TestReportAndHeartbeatBodies(t *testing.T) {
	r, err := New(agent, host(), []byte(sbomA))
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"protocol":1`, `"agent":{"version":"0.1.0","os":"linux","arch":"arm64"}`, `"hostIdSource":"machine-id"`, `"kernel":"6.1.0-47-arm64"`, `"osRelease":{"ID":"debian","VERSION_ID":"12"}`, `"reportHash":"` + r.ReportHash + `"`, `"sbom":{"bomFormat":"CycloneDX"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("report body lacks %s", want)
		}
	}
	hb := HeartbeatFor(r)
	if hb.Protocol != 1 || hb.Host.HostID != r.Host.HostID || hb.Host.Hostname != "web-1" || hb.ReportHash != r.ReportHash {
		t.Errorf("heartbeat %+v", hb)
	}
}

func TestGzipRoundTrip(t *testing.T) {
	body := []byte(strings.Repeat(sbomA, 50))
	gz, err := Gzip(body)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(zr)
	if !bytes.Equal(back, body) || len(gz) >= len(body) {
		t.Fatalf("round trip: %d bytes back of %d, %d compressed", len(back), len(body), len(gz))
	}
}
