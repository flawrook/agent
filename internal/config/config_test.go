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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

const fullFile = `url: https://file.example
token: flra_file
hostname: file-host
ca_file: /file/ca.pem
https_proxy: http://file-proxy:3128
no_proxy: file.internal
`

func TestPrecedenceFlagThenEnvThenFile(t *testing.T) {
	path := writeFile(t, fullFile)
	cases := []struct {
		name  string
		flags map[string]string
		env   map[string]string
		want  Config
	}{
		{"the file alone", nil, nil, Config{URL: "https://file.example", Token: "flra_file", Hostname: "file-host", CAFile: "/file/ca.pem", HTTPSProxy: "http://file-proxy:3128", NoProxy: "file.internal"}},
		{
			"the environment over the file",
			nil,
			map[string]string{"FLAWROOK_URL": "https://env.example", "FLAWROOK_TOKEN": "flra_env", "FLAWROOK_HOSTNAME": "env-host", "FLAWROOK_CA_FILE": "/env/ca.pem", "HTTPS_PROXY": "http://env-proxy:3128", "NO_PROXY": "env.internal"},
			Config{URL: "https://env.example", Token: "flra_env", Hostname: "env-host", CAFile: "/env/ca.pem", HTTPSProxy: "http://env-proxy:3128", NoProxy: "env.internal"},
		},
		{
			"a flag over the environment, the rest from the environment and the file",
			map[string]string{"token": "flra_flag", "ca_file": "/flag/ca.pem"},
			map[string]string{"FLAWROOK_TOKEN": "flra_env", "FLAWROOK_URL": "https://env.example"},
			Config{URL: "https://env.example", Token: "flra_flag", Hostname: "file-host", CAFile: "/flag/ca.pem", HTTPSProxy: "http://file-proxy:3128", NoProxy: "file.internal"},
		},
		{
			"a flag given empty clears the setting",
			map[string]string{"hostname": ""},
			map[string]string{"FLAWROOK_HOSTNAME": "env-host"},
			Config{URL: "https://file.example", Token: "flra_file", Hostname: "", CAFile: "/file/ca.pem", HTTPSProxy: "http://file-proxy:3128", NoProxy: "file.internal"},
		},
		{
			"the lowercase proxy variables count too, the uppercase first",
			nil,
			map[string]string{"https_proxy": "http://lower:3128", "no_proxy": "lower.internal"},
			Config{URL: "https://file.example", Token: "flra_file", Hostname: "file-host", CAFile: "/file/ca.pem", HTTPSProxy: "http://lower:3128", NoProxy: "lower.internal"},
		},
		{
			"uppercase wins over lowercase",
			nil,
			map[string]string{"HTTPS_PROXY": "http://upper:3128", "https_proxy": "http://lower:3128"},
			Config{URL: "https://file.example", Token: "flra_file", Hostname: "file-host", CAFile: "/file/ca.pem", HTTPSProxy: "http://upper:3128", NoProxy: "file.internal"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Load(Sources{Flags: c.flags, Env: env(c.env), Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestNoFileIsFineAndTheURLDefaults(t *testing.T) {
	got, err := Load(Sources{Env: env(map[string]string{"FLAWROOK_TOKEN": "flra_env"}), Path: filepath.Join(t.TempDir(), "absent.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, Config{URL: "https://flawrook.dev", Token: "flra_env"}) {
		t.Fatalf("got %+v", got)
	}
	empty, err := Load(Sources{Env: env(nil), Path: writeFile(t, "")})
	if err != nil || empty.URL != DefaultURL {
		t.Fatalf("an empty file: %+v %v", empty, err)
	}
}

func TestABadFileIsAnError(t *testing.T) {
	for name, text := range map[string]string{
		"a misspelt key": "url: https://a.example\ntokn: flra_x\n",
		"not YAML":       "url: [\n",
	} {
		if _, err := Load(Sources{Env: env(nil), Path: writeFile(t, text)}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	dir := t.TempDir() // a directory where the file should be: unreadable
	if _, err := Load(Sources{Env: env(nil), Path: dir}); err == nil {
		t.Error("an unreadable file: no error")
	}
}

func TestURLHTTPSOnlyButLoopback(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://flawrook.dev":         true,
		"https://flawrook.dev/":        true,
		"https://10.0.0.5:8443":        true,
		"http://localhost:3003":        true,
		"http://127.0.0.1:3003":        true,
		"http://[::1]:3003":            true,
		"http://flawrook.dev":          false,
		"http://10.0.0.5:3003":         false,
		"http://localhost.example.com": false,
		"ftp://flawrook.dev":           false,
		"flawrook.dev":                 false,
	} {
		got, err := Load(Sources{Flags: map[string]string{"url": raw}, Env: env(nil), Path: filepath.Join(t.TempDir(), "absent.yaml")})
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", raw, err, ok)
		}
		if ok && strings.HasSuffix(got.URL, "/") {
			t.Errorf("%s: trailing slash kept: %s", raw, got.URL)
		}
	}
}

func TestIncludeMounts(t *testing.T) {
	path := writeFile(t, "include_mounts:\n  - /srv/data/\n  - /mnt/team share\n")
	got, err := Load(Sources{Env: env(nil), Path: path})
	if err != nil || !reflect.DeepEqual(got.IncludeMounts, []string{"/srv/data", "/mnt/team share"}) {
		t.Fatalf("the file's list: %q %v", got.IncludeMounts, err)
	}
	got, _ = Load(Sources{Env: env(map[string]string{"FLAWROOK_INCLUDE_MOUNTS": "/a, /b/"}), Path: path})
	if !reflect.DeepEqual(got.IncludeMounts, []string{"/a", "/b"}) {
		t.Fatalf("the environment over the file: %q", got.IncludeMounts)
	}
	got, _ = Load(Sources{Flags: map[string]string{"include_mounts": "/c"}, Env: env(map[string]string{"FLAWROOK_INCLUDE_MOUNTS": "/a"}), Path: path})
	if !reflect.DeepEqual(got.IncludeMounts, []string{"/c"}) {
		t.Fatalf("a flag over the environment: %q", got.IncludeMounts)
	}
	got, _ = Load(Sources{Flags: map[string]string{"include_mounts": ""}, Env: env(nil), Path: path})
	if got.IncludeMounts != nil {
		t.Fatalf("an empty flag clears it: %q", got.IncludeMounts)
	}
	if _, err := Load(Sources{Env: env(nil), Path: writeFile(t, "include_mounts:\n  - srv/data\n")}); err == nil {
		t.Fatal("a relative path is accepted")
	}
	a, _ := Load(Sources{Env: env(nil), Path: path})
	b, _ := Load(Sources{Env: env(nil), Path: writeFile(t, "include_mounts:\n  - /srv/data\n")})
	if a.Equal(b) || !a.Equal(a) {
		t.Fatal("Equal doesn't see a changed include_mounts (SIGHUP would miss it)")
	}
}
