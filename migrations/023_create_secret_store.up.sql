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

-- Neutral secret catalog. Values are sealed before HTTP upload; no reveal endpoint exists.
CREATE TABLE secret_catalog_objects (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 kind TEXT NOT NULL CHECK (kind IN ('SECRET','GROUP')),
 owner_id UUID NOT NULL REFERENCES users(id),
 alias VARCHAR(100) NOT NULL CHECK (length(btrim(alias)) > 0),
 description VARCHAR(1000) NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
 archived BOOLEAN NOT NULL DEFAULT false,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX secret_catalog_owner_alias ON secret_catalog_objects(owner_id, kind, lower(alias));
CREATE TABLE secret_store_versions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 secret_id UUID NOT NULL REFERENCES secret_catalog_objects(id),
 version INTEGER NOT NULL CHECK (version > 0),
 state TEXT NOT NULL DEFAULT 'RESERVED' CHECK (state IN ('RESERVED','SEALED')),
 sealed_payload JSONB,
 byte_length INTEGER CHECK (byte_length BETWEEN 0 AND 65536),
 created_by UUID NOT NULL REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(secret_id,version),
 CHECK ((state = 'RESERVED' AND sealed_payload IS NULL AND byte_length IS NULL)
     OR (state = 'SEALED' AND sealed_payload IS NOT NULL AND byte_length IS NOT NULL))
);
CREATE TABLE secret_group_revisions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 group_id UUID NOT NULL REFERENCES secret_catalog_objects(id),
 revision INTEGER NOT NULL CHECK (revision > 0),
 created_by UUID NOT NULL REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(group_id,revision)
);
CREATE TABLE secret_group_members (
 group_revision_id UUID NOT NULL REFERENCES secret_group_revisions(id),
 version_id UUID NOT NULL REFERENCES secret_store_versions(id),
 PRIMARY KEY(group_revision_id,version_id)
);
CREATE TABLE secret_store_grants (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 object_id UUID NOT NULL REFERENCES secret_catalog_objects(id),
 grantee_id UUID NOT NULL REFERENCES users(id),
 permission TEXT NOT NULL CHECK (permission IN ('VIEW','PREPARE','WRITE_VERSION')),
 build_id UUID REFERENCES builds(id),
 granted_by UUID NOT NULL REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX secret_grants_global_unique ON secret_store_grants(object_id,grantee_id,permission) WHERE build_id IS NULL;
CREATE UNIQUE INDEX secret_grants_build_unique ON secret_store_grants(object_id,grantee_id,permission,build_id) WHERE build_id IS NOT NULL;
CREATE INDEX secret_grants_subject ON secret_store_grants(grantee_id,object_id);
CREATE TABLE build_secret_source_sets (
 build_id UUID PRIMARY KEY REFERENCES builds(id),
 revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE build_secret_sources (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 build_id UUID NOT NULL REFERENCES builds(id),
 secret_id UUID NOT NULL REFERENCES secret_catalog_objects(id),
 version_id UUID NOT NULL REFERENCES secret_store_versions(id),
 group_revision_id UUID REFERENCES secret_group_revisions(id),
 added_by UUID NOT NULL REFERENCES users(id),
 added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(build_id,secret_id)
);
CREATE INDEX build_secret_sources_build ON build_secret_sources(build_id);
-- Application audit (including global catalog actions), without secret values.
CREATE TABLE secret_store_events (
 id BIGSERIAL PRIMARY KEY,
 actor_id UUID NOT NULL REFERENCES users(id),
 action TEXT NOT NULL,
 object_id UUID,
 build_id UUID REFERENCES builds(id),
 details JSONB NOT NULL DEFAULT '{}',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
