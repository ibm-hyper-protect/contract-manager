#!/bin/sh
# Copyright (c) 2026 IBM Corp.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

cd "$(dirname "$0")/.."
sqlc generate

# SQLC has no file-header option. Carry license headers from the SQL sources
# into generated query files without changing their generated implementation.
for generated in internal/repository/*.sql.go; do
    [ -f "$generated" ] || continue
    source="internal/repository/queries/$(basename "$generated" .go)"
    [ -f "$source" ] || continue
    head -n 1 "$source" | grep -q '^-- Copyright (c)' || continue

    temporary=$(mktemp "${generated}.XXXXXX")
    trap 'rm -f "$temporary"' 0
    trap 'exit 1' HUP INT TERM
    awk '
        !/^--( |$)/ { exit }
        { sub(/^--/, "//"); print }
        END { print "" }
    ' "$source" > "$temporary"
    cat "$generated" >> "$temporary"
    chmod 644 "$temporary"
    mv "$temporary" "$generated"
    trap - 0 HUP INT TERM
done
