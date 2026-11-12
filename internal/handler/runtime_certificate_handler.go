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
	"errors"
	"net/http"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

// GetEncryptionCertificate handles exact platform/version lookup for embedded public certificates.
func (h *ContractHandler) GetEncryptionCertificate(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["platform"]) != 1 || len(query["version"]) != 1 {
		writeError(w, model.ErrInvalidRequest("provide one platform and one version"))
		return
	}
	cert, err := h.contractService.GetEncryptionCertificate(r.Context(), query.Get("platform"), query.Get("version"))
	if err != nil {
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to load runtime encryption certificate."))
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, cert)
}
