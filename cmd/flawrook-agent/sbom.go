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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"flawrook.dev/agent/internal/cluster"
	"flawrook.dev/agent/internal/config"
)

// The sbom subcommand's exit statuses besides 0: a read or catalog error, and an image or SBOM over its cap.
const (
	exitError = 1
	exitCap   = 2
)

// runSBOM is `flawrook-agent sbom <archive>`: the CycloneDX SBOM of a built image, from a Docker or OCI archive or an
// OCI layout directory, for a CI job to send to FlawRook with its own token. It reads no config file and no token,
// and connects to nothing.
func runSBOM(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flawrook-agent sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "the file to write the SBOM to (default stdout)")
	opt := cluster.ArchiveOptions{}
	fs.Int64Var(&opt.MaxImageBytes, "max-image-bytes", config.DefaultSBOMMaxImageBytes, "the largest image read, by its layers as the archive stores them")
	fs.StringVar(&opt.Platform, "platform", "linux/amd64", "the image to take from an OCI index of several platforms")
	fs.StringVar(&opt.Ref, "ref", "", "the image's name in the SBOM when the archive names none, such as registry.acme.example/shop:1.4")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: flawrook-agent sbom [flags] <archive>\n\n"+
			"The CycloneDX SBOM of a built image, from a docker archive (docker save), an OCI archive\n"+
			"(docker buildx build -o type=oci) or an OCI layout directory. Exit 1 on a read or catalog error,\n"+
			"2 when the image or its SBOM is over its limit; each with one line on stderr.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	var paths []string
	for { // flags may come after the archive too
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return exitError
		}
		if fs.NArg() == 0 {
			break
		}
		paths, args = append(paths, fs.Arg(0)), fs.Args()[1:]
	}
	if len(paths) != 1 {
		fmt.Fprintln(stderr, "flawrook-agent sbom: give one archive: flawrook-agent sbom [flags] <archive>")
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sbom, err := cluster.ArchiveSBOM(ctx, paths[0], opt, version)
	var capped *cluster.CapError
	switch {
	case errors.As(err, &capped):
		fmt.Fprintln(stderr, capped.Line)
		return exitCap
	case err != nil:
		fmt.Fprintf(stderr, "%s: %v\n", paths[0], err)
		return exitError
	}
	if *out == "" {
		_, err = stdout.Write(append(sbom, '\n'))
	} else {
		err = os.WriteFile(*out, append(sbom, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, "flawrook-agent sbom:", err)
		return exitError
	}
	return 0
}
