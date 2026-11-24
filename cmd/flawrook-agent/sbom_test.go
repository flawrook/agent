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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// A docker archive of a one-package Alpine-like image, as go-containerregistry writes it.
func archive(t *testing.T) string {
	t.Helper()
	img, err := crane.Image(map[string][]byte{
		"etc/os-release":       []byte("ID=alpine\nVERSION_ID=3.20.3\n"),
		"lib/apk/db/installed": []byte("P:musl\nV:1.2.5-r0\nA:x86_64\nL:MIT\no:musl\n\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(p, name.MustParseReference("registry.acme.example/shop:1.0"), img); err != nil {
		t.Fatal(err)
	}
	return p
}

func sbomRun(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runSBOM(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestTheSBOMSubcommand(t *testing.T) {
	p := archive(t)
	code, out, errs := sbomRun(p)
	var doc struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
	}
	if code != 0 || errs != "" || json.Unmarshal([]byte(out), &doc) != nil || doc.SpecVersion != "1.7" || doc.Metadata.Component.Name != "registry.acme.example/shop:1.0" {
		t.Fatalf("exit %d, stderr %q, %+v", code, errs, doc)
	}
	// --out, after the archive.
	file := filepath.Join(t.TempDir(), "sbom.json")
	if code, out, errs := sbomRun(p, "--out", file); code != 0 || out != "" || errs != "" {
		t.Fatalf("--out: exit %d, %q, %q", code, out, errs)
	}
	if b, err := os.ReadFile(file); err != nil || !bytes.Contains(b, []byte(`"specVersion":"1.7"`)) {
		t.Fatalf("--out file: %v %.80s", err, b)
	}

	junk := filepath.Join(t.TempDir(), "image.tar")
	os.WriteFile(junk, []byte(strings.Repeat("x", 2048)), 0o644)
	for _, tc := range []struct {
		args []string
		code int
		line string // stderr's first line, or a prefix of it ending in "…"
	}{
		{[]string{"--max-image-bytes", "1", p}, 2, "too large: …"},
		{[]string{junk}, 1, junk + ": not a Docker or OCI archive"},
		{[]string{filepath.Join(t.TempDir(), "none.tar")}, 1, "…no such file or directory"},
		{nil, 1, "flawrook-agent sbom: give one archive: flawrook-agent sbom [flags] <archive>"},
		{[]string{p, p}, 1, "flawrook-agent sbom: give one archive: flawrook-agent sbom [flags] <archive>"},
		{[]string{"--url", "https://flawrook.test", p}, 1, "flag provided but not defined: -url"},
	} {
		code, out, errs := sbomRun(tc.args...)
		first, _, _ := strings.Cut(errs, "\n")
		ok := first == tc.line ||
			(strings.HasSuffix(tc.line, "…") && strings.HasPrefix(first, strings.TrimSuffix(tc.line, "…"))) ||
			(strings.HasPrefix(tc.line, "…") && strings.HasSuffix(first, strings.TrimPrefix(tc.line, "…")))
		if code != tc.code || out != "" || !ok {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", tc.args, code, out, errs)
		}
	}
	if code, out, errs := sbomRun("--help"); code != 0 || out != "" || !strings.HasPrefix(errs, "Usage: flawrook-agent sbom [flags] <archive>") ||
		!strings.Contains(errs, "-max-image-bytes int") || !strings.Contains(errs, "(default 314572800)") || !strings.Contains(errs, "-platform string") ||
		!strings.Contains(errs, "-ref string") || !strings.Contains(errs, "-out string") {
		t.Errorf("--help: exit %d, %q, %s", code, out, errs)
	}
}

// run() with these arguments, its stderr captured.
func runWith(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldArgs, oldErr := os.Args, os.Stderr
	os.Args, os.Stderr = append([]string{"flawrook-agent"}, args...), w
	defer func() { os.Args, os.Stderr = oldArgs, oldErr }()
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := run()
	w.Close()
	return code, <-done
}

func TestTheSubcommandIsListedAndDispatched(t *testing.T) {
	if _, errs := runWith(t, "--help"); !strings.Contains(errs, "flawrook-agent sbom [flags] <archive>") || !strings.Contains(errs, "-dry-run") {
		t.Errorf("the agent's --help: %s", errs)
	}
	if code, errs := runWith(t, "sbom", "--help"); code != 0 || !strings.HasPrefix(errs, "Usage: flawrook-agent sbom") {
		t.Errorf("sbom --help: exit %d, %s", code, errs)
	}
}
