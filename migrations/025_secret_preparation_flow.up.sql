-- Copyright (c) 2026 IBM Corp.
-- All rights reserved.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Versioned public deployment artifacts and purpose-bound personal approvals.
CREATE TABLE deployment_targets (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_id UUID NOT NULL REFERENCES users(id),
 name VARCHAR(100) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE deployment_target_revisions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 target_id UUID NOT NULL REFERENCES deployment_targets(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 manifest JSONB NOT NULL,
 digest TEXT NOT NULL,
 created_by UUID NOT NULL REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(target_id,revision)
);
CREATE TABLE build_secret_flow (
 build_id UUID PRIMARY KEY REFERENCES builds(id) ON DELETE CASCADE,
 target_revision_id UUID REFERENCES deployment_target_revisions(id),
 revision INTEGER NOT NULL DEFAULT 0,
 requirements JSONB NOT NULL DEFAULT '[]',
 target_approval JSONB,
 target_evidence JSONB,
 prepared_digest TEXT,
 prepared_payload JSONB,
 prepared_by UUID REFERENCES users(id),
 frozen BOOLEAN NOT NULL DEFAULT false,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE build_secret_approvals (
 build_id UUID NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
 logical_name VARCHAR(64) NOT NULL,
 version_id UUID NOT NULL REFERENCES secret_store_versions(id),
 owner_id UUID NOT NULL REFERENCES users(id),
 target_revision_id UUID NOT NULL REFERENCES deployment_target_revisions(id),
 consumer VARCHAR(100) NOT NULL,
 secret_kind TEXT NOT NULL CHECK(secret_kind IN ('retrievable','association')),
 secret_type TEXT NOT NULL,
 proof JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(build_id,logical_name),
 UNIQUE(build_id,version_id)
);
CREATE TABLE secret_preparation_jobs (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 build_id UUID NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
 actor_id UUID NOT NULL REFERENCES users(id),
 manifest_digest TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('PREPARING','PREPARED','FAILED','STALE')),
 error_code TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 finished_at TIMESTAMPTZ
);
CREATE INDEX secret_preparation_jobs_build ON secret_preparation_jobs(build_id,created_at DESC);
