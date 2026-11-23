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

-- 022_allow_multiple_assignments_per_role.up.sql
-- Allows several users to hold the same persona role on one build (e.g. two auditors).
-- Any assigned user of the role may perform that role's workflow step; a user can still
-- be assigned to a given role only once per build.

ALTER TABLE build_assignments DROP CONSTRAINT IF EXISTS build_assignments_build_id_role_id_key;

ALTER TABLE build_assignments
    ADD CONSTRAINT build_assignments_build_id_role_id_user_id_key UNIQUE (build_id, role_id, user_id);
