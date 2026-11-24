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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func (h *SecretStoreHandler) RegisterFlowRoutes(r chi.Router) {
	r.Get("/secret-flow", h.Flow)
	r.With(middleware.RequireRole("ENV_OPERATOR")).Put("/secret-flow/target", h.FlowTarget)
	r.With(middleware.RequireRole("SOLUTION_PROVIDER")).Put("/secret-flow/requirements", h.FlowRequirements)
	r.With(middleware.RequireRole("AUDITOR")).Put("/secret-flow/target-approval", h.FlowTargetApproval)
	r.With(middleware.RequireRole("ADMIN", "AUDITOR", "SOLUTION_PROVIDER", "DATA_OWNER", "ENV_OPERATOR")).Put("/secret-flow/approvals", h.FlowApprovals)
	r.With(middleware.RequireRole("AUDITOR")).Post("/secret-flow/prepare", h.FlowPrepare)
}
func flowBody(r *http.Request, dst any) (secretflow.Proof, error) {
	raw, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, 2*1024*1024))
	if e != nil {
		return secretflow.Proof{}, model.ErrInvalidRequest("Target artifacts exceed the size limit.")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(dst); e != nil {
		return secretflow.Proof{}, model.ErrInvalidRequest("Invalid secret-flow request.")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return secretflow.Proof{}, model.ErrInvalidRequest("Provide one JSON request.")
	}
	// Preserve raw signed data as bytes: JSONB would otherwise reorder its keys.
	var body json.RawMessage
	if e = json.Unmarshal(raw, &body); e != nil {
		return secretflow.Proof{}, e
	}
	k, ok := service.SigningKeyFromContext(r.Context())
	if !ok {
		return secretflow.Proof{}, model.ErrForbidden("An authenticated request-signing key is required.")
	}
	ts, e := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
	if e != nil {
		return secretflow.Proof{}, model.ErrInvalidRequest("Invalid approval timestamp.")
	}
	p := secretflow.Proof{SignerID: k.UserID, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint, Method: r.Method, Path: r.URL.Path, Body: []byte(body), Timestamp: ts, Hash: middleware.GetRequestSignatureHash(r.Context()), Signature: middleware.GetRequestSignature(r.Context())}
	return p, nil
}
func (h *SecretStoreHandler) Flow(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		return h.service.Flow(r.Context(), a, id)
	})
}
func (h *SecretStoreHandler) FlowTarget(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		var in struct {
			ExpectedRevision int32             `json:"expected_revision"`
			Target           secretflow.Target `json:"target"`
			Reuse            uuid.UUID         `json:"target_revision_id"`
		}
		if _, e = flowBody(r, &in); e != nil {
			return nil, e
		}
		return h.service.SetFlowTarget(r.Context(), a, id, in.ExpectedRevision, in.Target, in.Reuse)
	})
}
func (h *SecretStoreHandler) FlowRequirements(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		var in struct {
			ExpectedRevision int32                    `json:"expected_revision"`
			Requirements     []secretflow.Requirement `json:"requirements"`
		}
		if _, e = flowBody(r, &in); e != nil {
			return nil, e
		}
		return h.service.SetFlowRequirements(r.Context(), a, id, in.ExpectedRevision, in.Requirements)
	})
}
func (h *SecretStoreHandler) FlowTargetApproval(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		var in struct {
			ExpectedRevision int32     `json:"expected_revision"`
			TargetRevisionID uuid.UUID `json:"target_revision_id"`
			TargetDigest     string    `json:"target_digest"`
			Confirmed        bool      `json:"header_provenance_confirmed"`
		}
		p, e := flowBody(r, &in)
		if e != nil {
			return nil, e
		}
		return h.service.ApproveFlowTarget(r.Context(), a, id, in.ExpectedRevision, p)
	})
}
func (h *SecretStoreHandler) FlowApprovals(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		var in secretflow.Approval
		p, e := flowBody(r, &in)
		if e != nil {
			return nil, e
		}
		return h.service.ApproveFlowSources(r.Context(), a, id, in, p)
	})
}
func (h *SecretStoreHandler) FlowPrepare(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) {
		id, e := secretParam(r, "id")
		if e != nil {
			return nil, e
		}
		var in struct {
			ExpectedRevision int32 `json:"expected_revision"`
		}
		if e = secretBody(r, &in); e != nil {
			return nil, e
		}
		return h.service.PrepareFlow(r.Context(), a, id, in.ExpectedRevision)
	})
}
func (h *SecretStoreHandler) FlowTargets(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, 200, func(a service.SecretActor) (any, error) { return h.service.Targets(r.Context(), a) })
}
