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

// Package validation checks plaintext sections against the embedded CCRT schema.
package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	contractschema "github.com/ibm-hyper-protect/contract-go/v3/schema/contract"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

var ccrtSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	resource, err := jsonschema.UnmarshalJSON(strings.NewReader(contractschema.ContractSchemaCcrt))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	const location = "https://contract-manager.local/schema/ccrt.json"
	if err := compiler.AddResource(location, resource); err != nil {
		return nil, err
	}
	return compiler.Compile(location)
})

// ParseMapping rejects duplicate keys, multiple documents, scalar roots and
// non-string YAML map keys. JSON conversion also normalizes numbers for the schema.
func ParseMapping(text string) (map[string]any, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("YAML must contain a non-empty mapping")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("provide exactly one YAML document")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("YAML must use string mapping keys and JSON-compatible values")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func sectionMap(value any, kind string) (map[string]any, error) {
	var section map[string]any
	var err error
	switch value := value.(type) {
	case string:
		section, err = ParseMapping(value)
	case map[string]any:
		section = value
	default:
		return nil, fmt.Errorf("%s must be a YAML mapping or a block scalar containing YAML", kind)
	}
	if err != nil {
		return nil, err
	}
	if section["type"] != kind {
		return nil, fmt.Errorf("section must have type: %s", kind)
	}
	if kind == "workload" {
		if play, ok := section["play"].(map[string]any); ok {
			archive, _ := play["archive"].(string)
			resources, _ := play["resources"].([]any)
			templates, _ := play["templates"].([]any)
			if strings.TrimSpace(archive) == "" && len(resources) == 0 && len(templates) == 0 {
				return nil, fmt.Errorf("Podman play requires an archive, resources or templates")
			}
		}
	}
	return section, nil
}

// Validate accepts one raw section or a complete plaintext contract. Complete
// input is always checked as a pair, even when only one section is requested.
// An env section's nested env map is environment variables, not a contract wrapper.
func Validate(text, kind string) (map[string]any, error) {
	if kind != "" && kind != "workload" && kind != "env" {
		return nil, fmt.Errorf("section must be workload, env or empty for both")
	}
	root, err := ParseMapping(text)
	if err != nil {
		return nil, err
	}
	data := make(map[string]any)
	if _, raw := root["type"]; raw {
		if kind == "" {
			return nil, fmt.Errorf("complete validation requires both workload and env sections")
		}
		section, err := sectionMap(root, kind)
		if err != nil {
			return nil, err
		}
		data[kind] = section
	} else {
		if len(root) != 2 || root["env"] == nil || root["workload"] == nil {
			return nil, fmt.Errorf("provide raw section YAML or a complete plaintext contract with workload and env")
		}
		for _, name := range []string{"workload", "env"} {
			section, err := sectionMap(root[name], name)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			data[name] = section
		}
	}
	schema, err := ccrtSchema()
	if err != nil {
		return nil, fmt.Errorf("load contract schema: %w", err)
	}
	if err := schema.Validate(data); err != nil {
		return nil, fmt.Errorf("contract schema validation failed: %w", err)
	}
	if workload, ok := data["workload"].(map[string]any); ok {
		if env, ok := data["env"].(map[string]any); ok {
			if err := validateVolumePair(workload, env); err != nil {
				return nil, err
			}
		}
	}
	if kind == "" {
		return data, nil
	}
	return data[kind].(map[string]any), nil
}

// Volume seeds may be split between personas. Compare their declarations when
// both plaintext sections are available, before either section is encrypted.
func validateVolumePair(workload, env map[string]any) error {
	wvolumes, _ := workload["volumes"].(map[string]any)
	evolumes, _ := env["volumes"].(map[string]any)
	for name, item := range wvolumes {
		volume, _ := item.(map[string]any)
		counterpart, _ := evolumes[name].(map[string]any)
		seed, _ := volume["seed"].(string)
		other, _ := counterpart["seed"].(string)
		if seed == "" && other == "" {
			return fmt.Errorf("volume %q needs a seed in workload or env", name)
		}
	}
	for name := range evolumes {
		if _, ok := wvolumes[name]; !ok {
			return fmt.Errorf("env volume %q has no workload declaration", name)
		}
	}
	return nil
}

// MarshalSection encodes a validated section or plaintext contract as YAML.
func MarshalSection(section map[string]any) (string, error) {
	data, err := yaml.Marshal(section)
	return string(data), err
}
