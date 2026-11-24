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

package service

import (
	"bytes"
	"context"

	"github.com/google/uuid"
	hpcontract "github.com/ibm-hyper-protect/contract-go/v3/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/validation"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/jackc/pgx/v5"
)

func (s *ContractService) preparedForSection(ctx context.Context, id uuid.UUID, cert string) (secretflow.Job, secretflow.Result, error) {
	// Keep the pre-encryption snapshot consistent; publication rechecks it under the build lock.
	var j secretflow.Job
	var r secretflow.Result
	begin, ok := s.db.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return j, r, model.ErrInternal("Secret preparation requires database transactions.")
	}
	tx, e := begin.Begin(ctx)
	if e != nil {
		return j, r, e
	}
	defer tx.Rollback(ctx)
	q := repository.New(tx)
	if _, e = q.LockSecretBuild(ctx, id); e != nil {
		return j, r, e
	}
	j, r, e = validatePrepared(ctx, q, id)
	if e != nil {
		return j, r, flowDomain(e)
	}
	if j.BuildID != uuid.Nil && cert != "" {
		a, e1 := secretflow.Certificates([]byte(cert))
		b, e2 := secretflow.Certificates([]byte(j.Target.RuntimeCertificate))
		if e1 != nil || e2 != nil || len(a) != 1 || len(b) != 1 || !bytes.Equal(a[0].Raw, b[0].Raw) {
			return j, r, flowError("SECRET_RUNTIME_CERT_MISMATCH", "Use the runtime encryption certificate pinned in the approved deployment target.", 422)
		}
	}
	return j, r, nil
}
func environmentWithPrepared(env string, j secretflow.Job, r secretflow.Result) (string, error) {
	env, e := environmentWithSecretIDs(env, r.Artifacts)
	if e != nil {
		return "", e
	}
	options := hpcontract.RetrievableSecretsOptions{Hosts: map[string]hpcontract.HostKeyDocument{}}
	for _, h := range j.Target.Hosts {
		options.Hosts[h.ID] = hpcontract.HostKeyDocument{Description: h.Description, Data: h.Data}
	}
	for _, a := range r.Artifacts {
		options.Requests = append(options.Requests, hpcontract.RetrievableSecretRequest{Data: a.Data, Certificate: a.Certificate, ExpectedSecretID: a.SecretID})
	}
	out, e := hpcontract.WithRetrievableSecrets(env, j.Target.Platform, options)
	if e != nil {
		return "", flowError("SECRET_ENVIRONMENT_INVALID", "The environment conflicts with approved secret requests or fails the CCRV schema. Remove manually supplied uv-secrets/host-attestation and retain logging, environment variables and volumes.", 422)
	}
	return out, nil
}

// Values remain in encrypted requests. Only public UV identifiers are exposed
// as configuration, alongside the Data Owner's variables in the env section.
func environmentWithSecretIDs(env string, artifacts []secretflow.Artifact) (string, error) {
	section, err := validation.ParseMapping(env)
	if err != nil || section["type"] != "env" {
		return "", flowError("SECRET_ENVIRONMENT_INVALID", "Provide raw environment YAML starting with type: env.", 422)
	}
	variables, ok := section["env"].(map[string]any)
	if _, exists := section["env"]; exists && !ok {
		return "", flowError("SECRET_ENVIRONMENT_INVALID", "Environment variables must be a mapping in the environment section's env field.", 422)
	}
	if variables == nil {
		variables = map[string]any{}
	}
	for _, artifact := range artifacts {
		if err := (secretflow.Requirement{Name: artifact.Name, Consumer: artifact.Consumer, Kind: artifact.Kind, Type: artifact.Type}).Validate(); err != nil {
			return "", flowError("SECRET_ENVIRONMENT_INVALID", "Prepared secret metadata is invalid; prepare the requests again.", 422)
		}
		name := artifact.Name + "_SECRET_ID"
		if existing, exists := variables[name]; exists && existing != artifact.SecretID {
			return "", flowError("SECRET_ENVIRONMENT_BINDING_MISMATCH", "An environment variable conflicts with an approved UV secret ID. Remove the conflicting *_SECRET_ID variable or use the ID from Runtime secrets.", 422)
		}
		variables[name] = artifact.SecretID
	}
	if len(variables) > 0 {
		section["env"] = variables
	}
	out, err := validation.MarshalSection(section)
	if err != nil {
		return "", flowError("SECRET_ENVIRONMENT_INVALID", "The environment section could not be encoded.", 422)
	}
	return out, nil
}

const ccrvWorkloadTemplate = `type: workload
play:
  resources:
    - apiVersion: v1
      kind: Pod
      metadata:
        name: application
      spec:
        containers:
          - name: application
            image: registry.example/namespace/image:tag
`

func (s *ContractService) GetContractTemplateForProfile(ctx context.Context, kind, profile string) (string, string, error) {
	if profile == "" || profile == "ccrt" {
		return s.GetContractTemplate(ctx, kind)
	}
	if profile != "ccrv" {
		return "", "", model.ErrInvalidRequest("Unsupported contract profile.")
	}
	if kind == "workload" {
		return kind, ccrvWorkloadTemplate, nil
	}
	if kind == "env" {
		return s.GetContractTemplate(ctx, kind)
	}
	return "", "", model.ErrInvalidRequest("Template type must be workload or env.")
}

// RequiresSecretFlow is non-sensitive feature discovery for the existing build
// response. Ordinary/older builds need no catalog request or new TLS policy.
func (s *BuildService) RequiresSecretFlow(ctx context.Context, id uuid.UUID) (bool, error) {
	required, err := s.queries.BuildRequiresSecretFlow(ctx, id)
	if err != nil {
		return false, err
	}
	if required == nil {
		return false, model.ErrInternal("Build secret requirements are unavailable.")
	}
	return *required, nil
}
