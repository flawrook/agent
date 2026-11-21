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
	"bytes"
	"context"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source"
	_ "modernc.org/sqlite" // the rpm cataloger reads RHEL 9's rpmdb.sqlite through database/sql, as in inventory
)

// SBOM catalogs an image downloaded into an OCI layout: Syft's image catalogers (OS packages and the language
// ecosystems inside the image), less the linux-kernel cataloger. The source's name is the image reference, since
// the layout's own input is a temp path; its version is left to Syft, which writes the platform manifest digest
// into metadata.component.version, the digest the server checks the upload against.
func SBOM(ctx context.Context, layoutDir, ref, version string) ([]byte, int, error) {
	src, err := syft.GetSource(ctx, layoutDir, syft.DefaultGetSourceConfig().WithSources("oci-dir").WithAlias(source.Alias{Name: ref}))
	if err != nil {
		return nil, 0, err
	}
	defer src.Close()
	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("flawrook-agent", version).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults("image").WithRemovals("linux-kernel-cataloger")).
		WithoutFiles()
	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, 0, err
	}
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, 0, err
	}
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *s); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), s.Artifacts.Packages.PackageCount(), nil
}
