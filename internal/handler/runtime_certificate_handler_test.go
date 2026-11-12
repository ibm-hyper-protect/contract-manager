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

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	hpencryption "github.com/ibm-hyper-protect/contract-go/v3/encryption"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/contractgo"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func runtimeCertificateHandler() *ContractHandler {
	return NewContractHandler(service.NewContractService(nil, nil, nil, nil, nil, nil, contractgo.New()), nil)
}

func TestRuntimeCertificateCatalogHTTP(t *testing.T) {
	h := runtimeCertificateHandler()
	response := httptest.NewRecorder()
	h.ListAvailableEncCertVersions(response, httptest.NewRequest(http.MethodGet, "/v2/encryption-certificates/versions", nil))
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var catalog contract.CertificateCatalog
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Platforms) != 4 || len(catalog.Versions) == 0 {
		t.Fatalf("missing platform/legacy data: %s", response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("certificate catalog may be cached past validity")
	}
}

func TestRuntimeCertificateHTTPUsesExactPairAndRejectsInvalidChoices(t *testing.T) {
	h := runtimeCertificateHandler()
	for platform, versions := range hpencryption.CertificateMap {
		for version, text := range versions {
			query := url.Values{"platform": {platform}, "version": {version}}
			response := httptest.NewRecorder()
			h.GetEncryptionCertificate(response, httptest.NewRequest(http.MethodGet, "/v2/encryption-certificates/certificate?"+query.Encode(), nil))
			expected := http.StatusOK
			if validation.EncryptionCertificate(text) != nil {
				expected = http.StatusBadRequest
			}
			if response.Code != expected {
				t.Fatalf("%s/%s: %d %s", platform, version, response.Code, response.Body.String())
			}
			if expected == http.StatusOK {
				var cert contract.RuntimeCertificate
				if err := json.Unmarshal(response.Body.Bytes(), &cert); err != nil {
					t.Fatal(err)
				}
				if cert.CertificatePEM != text || !cert.NotAfter.After(time.Now()) {
					t.Fatal("wrong or expired certificate returned")
				}
			}
		}
	}
	validCCRTStatus := http.StatusOK
	if validation.EncryptionCertificate(hpencryption.CertificateMap["ccrt"]["26.7.2"]) != nil {
		validCCRTStatus = http.StatusBadRequest
	}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"", 400}, {"platform=ccrt", 400}, {"platform=&version=26.7.2", 400},
		{"platform=ccrt&platform=hpvs&version=26.7.2", 400},
		{"platform=ccrt&version=26.7.2&version=26.5.0", 400},
		{"platform=ccrt&version=missing", 404}, {"platform=ccrt&version=1.0.29", 404},
		{"platform=unknown&version=26.7.2", 404},
		{"platform=CCRT&version=26.7.2", validCCRTStatus},
	} {
		response := httptest.NewRecorder()
		h.GetEncryptionCertificate(response, httptest.NewRequest(http.MethodGet, "/v2/encryption-certificates/certificate?"+tc.query, nil))
		if response.Code != tc.status {
			t.Fatalf("%q: %d %s", tc.query, response.Code, response.Body.String())
		}
	}
}
