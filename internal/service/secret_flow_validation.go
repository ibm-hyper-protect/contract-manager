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
	hpcontract "github.com/ibm-hyper-protect/contract-go/v3/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
)

func validateResult(j secretflow.Job, r secretflow.Result) error {
	if r.Digest != j.Digest || r.Mode != j.Target.Mode || len(r.Artifacts) != len(j.Items) || r.Evidence.Mode != r.Mode || r.Evidence.HeaderDigest != j.Target.HeaderSHA256 {
		return secretflow.Fail("SECRET_RESULT_INVALID", "The worker result does not match the approved manifest.")
	}
	if r.Evidence.HardwareStatus != "NOT_TESTED_ON_TARGET" || (r.Mode == "NATIVE" && r.Evidence.HKDTrust != "IBM_TOOL_VERIFIED") || (r.Mode == "SIMULATION" && r.Evidence.HKDTrust != "UNVERIFIED_DEVELOPMENT_ONLY") {
		return secretflow.Fail("SECRET_RESULT_INVALID", "Worker evidence does not match the selected mode.")
	}
	seen := map[string]bool{}
	for i, a := range r.Artifacts {
		b := j.Items[i].Binding
		if a.Name != b.Name || a.Consumer != b.Consumer || a.Kind != b.Kind || a.Type != b.Type || len(a.Data) > 256*1024 {
			return secretflow.Fail("SECRET_RESULT_INVALID", "The returned request has an unexpected binding or size.")
		}
		info, e := hpcontract.InspectPreparedSecretRequest(a.Data)
		if e != nil || info.SecretID != a.SecretID || info.RequestSHA256 != a.RequestSHA256 || seen[a.SecretID] {
			return secretflow.Fail("SECRET_RESULT_INVALID", "The request ID, digest or format could not be verified.")
		}
		seen[a.SecretID] = true
		if !secretflow.MatchesUVType(a.Kind, a.Type, info.SecretType) {
			return secretflow.Fail("SECRET_RESULT_INVALID", "The returned UV secret kind is incorrect.")
		}
		if a.SecretID != "0x"+secretflow.Hash([]byte(secretflow.RequestName(j, b))) {
			return secretflow.Fail("SECRET_RESULT_INVALID", "The returned ID does not match this pinned build binding.")
		}
		if r.Mode == "NATIVE" && len(a.Certificate) == 0 {
			return secretflow.Fail("SECRET_RESULT_INVALID", "Native requests must include their worker verification certificate.")
		}
	}
	return nil
}
