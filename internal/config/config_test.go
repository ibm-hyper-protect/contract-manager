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

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func cleanRuntimeEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"DATABASE_URL", "SERVER_HOST", "SERVER_PORT", "TOKEN_EXPIRY", "BCRYPT_COST",
		"LOG_LEVEL", "LOG_FORMAT", "MAX_PAYLOAD_SIZE", "CORS_ALLOWED_ORIGINS",
		"CORS_ALLOW_ALL", "TRUST_PROXY_HEADERS", "REQUEST_TIMEOUT",
		"APPID_CLIENT_ID", "APPID_CLIENT_SECRET", "APPID_OAUTH_SERVER_URL", "APPID_REDIRECT_URI",
		"ADMIN_NAME", "ADMIN_EMAIL", "ADMIN_PASSWORD",
	} {
		t.Setenv(key, "")
	}
}

func TestInvalidRuntimeValuesHaveSafeErrorCodes(t *testing.T) {
	for _, tc := range []struct{ name, value, code, variable string }{
		{"SERVER_PORT", "invalid-sentinel", "CONFIG_INVALID_VALUE", "SERVER_PORT"},
		{"SERVER_PORT", "65536", "CONFIG_INVALID_VALUE", "SERVER_PORT"},
		{"BCRYPT_COST", "3", "CONFIG_INVALID_VALUE", "BCRYPT_COST"},
		{"MAX_PAYLOAD_SIZE", "0", "CONFIG_INVALID_VALUE", "MAX_PAYLOAD_SIZE"},
		{"TOKEN_EXPIRY", "-1h", "CONFIG_INVALID_VALUE", "TOKEN_EXPIRY"},
		{"REQUEST_TIMEOUT", "invalid-sentinel", "CONFIG_INVALID_VALUE", "REQUEST_TIMEOUT"},
		{"CORS_ALLOW_ALL", "invalid-sentinel", "CONFIG_INVALID_VALUE", "CORS_ALLOW_ALL"},
		{"TRUST_PROXY_HEADERS", "invalid-sentinel", "CONFIG_INVALID_VALUE", "TRUST_PROXY_HEADERS"},
		{"LOG_LEVEL", "invalid-sentinel", "CONFIG_INVALID_VALUE", "LOG_LEVEL"},
		{"LOG_FORMAT", "invalid-sentinel", "CONFIG_INVALID_VALUE", "LOG_FORMAT"},
		{"DATABASE_URL", "postgres://user:secret-sentinel@%invalid", "CONFIG_INVALID_VALUE", "DATABASE_URL"},
		{"ADMIN_EMAIL", "admin@example.com", "ADMIN_CONFIGURATION_INCOMPLETE", "ADMIN_PASSWORD"},
		{"ADMIN_PASSWORD", "secret-sentinel", "ADMIN_CONFIGURATION_INCOMPLETE", "ADMIN_EMAIL"},
		{"APPID_OAUTH_SERVER_URL", "https://user:secret-sentinel@id.example", "CONFIG_INVALID_VALUE", "APPID_OAUTH_SERVER_URL"},
		{"APPID_REDIRECT_URI", "/invalid-sentinel", "CONFIG_INVALID_VALUE", "APPID_REDIRECT_URI"},
	} {
		t.Run(tc.name+"/"+tc.variable+"/"+tc.value, func(t *testing.T) {
			cleanRuntimeEnv(t)
			t.Setenv("DATABASE_URL", "postgres://localhost/test")
			t.Setenv(tc.name, tc.value)
			_, err := Load()
			var cfgErr *Error
			if !errors.As(err, &cfgErr) || cfgErr.Code != tc.code || cfgErr.Variable != tc.variable {
				t.Fatalf("expected code %s on %s", tc.code, tc.variable)
			}
			if strings.Contains(err.Error(), "sentinel") {
				t.Fatal("configuration error disclosed a supplied value")
			}
		})
	}
}

func TestSSOFallbackReportsMissingNamesAndSupportsNativeRedirect(t *testing.T) {
	cleanRuntimeEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("APPID_CLIENT_ID", "runtime-client")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if names := cfg.IncompleteSSOFields(); len(names) != 3 || names[0] != "APPID_CLIENT_SECRET" {
		t.Fatal("partial SSO configuration must identify the missing settings")
	}
	t.Setenv("APPID_REDIRECT_URI", "com.example.application:/callback")
	if _, err := Load(); err != nil {
		t.Fatal("registered native application callback URLs must remain supported")
	}
}

func TestLoadDefaultsWithoutContractEnvironment(t *testing.T) {
	cleanRuntimeEnv(t)
	t.Setenv("DATABASE_URL", "postgres://existing-compose-value")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://existing-compose-value" || cfg.Addr() != "0.0.0.0:8080" {
		t.Fatal("existing container configuration or default listen address was lost")
	}
	if cfg.TokenExpiry != 24*time.Hour || cfg.BcryptCost != 12 || cfg.RequestTimeout != 30*time.Second {
		t.Fatal("runtime defaults changed")
	}
	if cfg.LogLevel != "info" || cfg.LogFormat != "json" || cfg.MaxPayloadSize != 50<<20 {
		t.Fatal("logging or payload defaults changed")
	}
	if cfg.CORSAllowAll || cfg.TrustProxyHeaders {
		t.Fatal("security defaults must remain restrictive")
	}
	if cfg.AppIDClientID != "" || cfg.AppIDClientSecret != "" || cfg.AppIDOAuthServerURL != "" || cfg.AppIDRedirectURI != "" {
		t.Fatal("missing SSO configuration must not acquire fallback credentials")
	}
}

func TestLoadRuntimeOverrides(t *testing.T) {
	cleanRuntimeEnv(t)
	values := map[string]string{
		"DATABASE_URL": "postgres://runtime-value", "SERVER_HOST": "127.0.0.1", "SERVER_PORT": "8091",
		"TOKEN_EXPIRY": "2h", "BCRYPT_COST": "13", "REQUEST_TIMEOUT": "45s",
		"LOG_LEVEL": "debug", "LOG_FORMAT": "text", "MAX_PAYLOAD_SIZE": "4096",
		"CORS_ALLOWED_ORIGINS": "https://one.example, https://two.example",
		"APPID_CLIENT_ID":      "runtime-client", "APPID_CLIENT_SECRET": "  exact-secret-value\n",
		"APPID_OAUTH_SERVER_URL": "https://id.example/oauth", "APPID_REDIRECT_URI": "https://app.example/callback",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != values["DATABASE_URL"] || cfg.Addr() != "127.0.0.1:8091" || cfg.TokenExpiry != 2*time.Hour || cfg.BcryptCost != 13 || cfg.RequestTimeout != 45*time.Second {
		t.Fatal("runtime connection or authentication settings were not honored")
	}
	if cfg.LogLevel != "debug" || cfg.LogFormat != "text" || cfg.MaxPayloadSize != 4096 || len(cfg.CORSAllowedOrigins) != 2 || cfg.CORSAllowedOrigins[1] != "https://two.example" {
		t.Fatal("runtime logging, payload or origin settings were not honored")
	}
	if cfg.AppIDClientID != values["APPID_CLIENT_ID"] || cfg.AppIDClientSecret != values["APPID_CLIENT_SECRET"] || cfg.AppIDOAuthServerURL != values["APPID_OAUTH_SERVER_URL"] || cfg.AppIDRedirectURI != values["APPID_REDIRECT_URI"] {
		t.Fatal("SSO settings must preserve the supplied values, including secret whitespace")
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	cleanRuntimeEnv(t)
	if _, err := Load(); err == nil {
		t.Fatal("missing database configuration must fail instead of using an embedded credential")
	}
}
