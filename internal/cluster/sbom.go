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

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/source"
	_ "modernc.org/sqlite" // the rpm cataloger reads RHEL 9's rpmdb.sqlite through database/sql, as in inventory
)

// CycloneDXVersion is the one version both SBOMs are written in: cluster mode's uploads and the sbom subcommand's.
const CycloneDXVersion = cyclonedx.SpecVersion1_7

// SBOMSource is an image on disk and how Syft opens it.
type SBOMSource struct {
	Tag      string          // Syft's source for its kind: "oci-dir", "oci-archive" or "docker-archive"
	Path     string          // a temp path in cluster mode, so the source's name is Name
	Name     string          // metadata.component.name: the image reference
	Key      string          // metadata.component.version when set; else Syft's, the platform manifest digest
	Platform *image.Platform // the image to take from an index of several; nil for an index of one, which it isn't checked against
	// Properties are added to metadata.properties.
	Properties []cyclonedx.Property
}

// SBOM catalogs one image, for cluster mode and the sbom subcommand alike: Syft's image catalogers (OS packages and
// the language ecosystems inside the image), less the linux-kernel cataloger, and no files. It answers the CycloneDX
// JSON, in CycloneDXVersion, and the package count. Cluster mode leaves Key empty: Syft writes the platform manifest
// digest into metadata.component.version, the digest the server checks the upload against.
func SBOM(ctx context.Context, in SBOMSource, version string) ([]byte, int, error) {
	get := syft.DefaultGetSourceConfig().WithSources(in.Tag).WithAlias(source.Alias{Name: in.Name, Version: in.Key})
	if in.Platform != nil {
		get = get.WithPlatform(in.Platform)
	}
	src, err := syft.GetSource(ctx, in.Path, get)
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
	// Syft's own CycloneDX JSON encoder does this too, with no way to add metadata properties.
	bom := cyclonedxhelpers.ToFormatModel(*s)
	if len(in.Properties) > 0 {
		var props []cyclonedx.Property
		if bom.Metadata.Properties != nil {
			props = *bom.Metadata.Properties
		}
		props = append(props, in.Properties...)
		bom.Metadata.Properties = &props
	}
	var buf bytes.Buffer
	enc := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(false)
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, CycloneDXVersion); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), s.Artifacts.Packages.PackageCount(), nil
}
