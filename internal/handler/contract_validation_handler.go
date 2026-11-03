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
	"net/http"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

// ValidateContract checks raw workload/env YAML or both plaintext sections.
// It never encrypts, persists, or logs the submitted plaintext.
func (h *ContractHandler) ValidateContract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plaintext string `json:"plaintext"`
		Section   string `json:"section"`
	}
	if err := readJSONLarge(r, &req, 50<<20); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}
	section, err := validation.Validate(req.Plaintext, req.Section)
	if err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}
	plaintext, err := validation.MarshalSection(section)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to encode validated YAML."))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "section": req.Section, "platform": "ccrt", "plaintext": plaintext})
}
