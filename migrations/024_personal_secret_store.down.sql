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

-- Rollback restores the old schema but never resurrects revoked permissions.
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
