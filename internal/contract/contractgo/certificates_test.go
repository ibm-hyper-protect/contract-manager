// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contractgo

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"testing"

	hpencryption "github.com/ibm-hyper-protect/contract-go/v3/encryption"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
)

func TestCertificateCatalogPreservesPlatformsAndLegacyVersions(t *testing.T) {
	e := New()
	catalog, err := e.ListEncryptionCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	unique := map[string]bool{}
	for _, platform := range catalog.Platforms {
		ids = append(ids, platform.ID)
		if platform.ContractSupported != (platform.ID == "ccrt") {
			t.Fatalf("misreported contract support: %+v", platform)
		}
		if len(platform.Versions) != len(hpencryption.CertificateMap[platform.ID]) {
			t.Fatal("lost platform versions")
		}
		for i, version := range platform.Versions {
			if _, ok := hpencryption.CertificateMap[platform.ID][version]; !ok {
				t.Fatalf("wrong platform membership: %s/%s", platform.ID, version)
			}
			if i > 0 && hpencryption.CompareVersions(platform.Versions[i-1], version) <= 0 {
				t.Fatal("versions not sorted newest first")
			}
			unique[version] = true
		}
	}
	if !slices.Equal(ids, []string{"ccco", "ccrt", "ccrv", "hpvs"}) {
		t.Fatalf("platform identifiers: %v", ids)
	}
	if len(catalog.Versions) != len(unique) {
		t.Fatal("legacy version list lost entries or has duplicates")
	}
	for _, version := range catalog.Versions {
		if !unique[version] {
			t.Fatal("legacy version not in any platform")
		}
	}
	expected, _ := json.Marshal(catalog)
	for i := 0; i < 20; i++ {
		again, err := e.ListEncryptionCertificates(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := json.Marshal(again)
		if string(actual) != string(expected) {
			t.Fatal("catalog order changed between requests")
		}
	}
}

func TestExactEmbeddedCertificateAndPublicMetadata(t *testing.T) {
	e := New()
	for platform, versions := range hpencryption.CertificateMap {
		for version, text := range versions {
			cert, err := e.GetEncryptionCertificate(context.Background(), platform, version)
			if err != nil {
				t.Fatalf("%s/%s: %v", platform, version, err)
			}
			if cert.CertificatePEM != text || cert.Platform != platform || cert.Version != version {
				t.Fatal("returned a different embedded certificate")
			}
			block, _ := pem.Decode([]byte(text))
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := sha256.Sum256(parsed.Raw)
			if cert.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) || !cert.NotBefore.Equal(parsed.NotBefore) || !cert.NotAfter.Equal(parsed.NotAfter) {
				t.Fatal("certificate metadata does not match PEM")
			}
		}
	}
	for _, choice := range [][2]string{{"ccrt", "1.0.29"}, {"invalid", "26.7.2"}, {"ccrt", "../../cert"}, {"", ""}} {
		_, err := e.GetEncryptionCertificate(context.Background(), choice[0], choice[1])
		if !errors.Is(err, contract.ErrCertificateNotFound) {
			t.Fatalf("unknown pair accepted: %v: %v", choice, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.ListEncryptionCertificates(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored canceled catalog request")
	}
	if _, err := e.GetEncryptionCertificate(ctx, "ccrt", "26.7.2"); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored canceled certificate request")
	}
}
func TestCccoReleasesMapFixpacksToModCertificate(t *testing.T) {
	catalog, err := New().ListEncryptionCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range catalog.Platforms {
		if platform.ID != "ccco" {
			if platform.Releases != nil {
				t.Fatalf("%s must not have releases", platform.ID)
			}
			continue
		}
		if len(platform.Releases) == 0 {
			t.Fatal("ccco has no releases")
		}
		for _, release := range platform.Releases {
			if release.Fixpacks == nil {
				t.Fatalf("fixpacks of %s must not be nil", release.Mod)
			}
			for _, fixpack := range release.Fixpacks {
				if hpencryption.CertificateMap["ccco"][fixpack] != hpencryption.CertificateMap["ccco"][release.Mod] {
					t.Fatalf("fixpack %s does not use the certificate of mod %s", fixpack, release.Mod)
				}
			}
		}
	}
}
