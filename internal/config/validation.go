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
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Error is safe to log: it contains setting names and fixed messages, never values.
type Error struct {
	Code     string
	Variable string
	Message  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s: %s", e.Code, e.Variable, e.Message) }

func invalid(variable, message string) error {
	return &Error{Code: "CONFIG_INVALID_VALUE", Variable: variable, Message: message}
}

func validateEnvironment() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return &Error{Code: "CONFIG_REQUIRED", Variable: "DATABASE_URL", Message: "set DATABASE_URL in the backend container environment"}
	}
	if _, err := pgxpool.ParseConfig(dsn); err != nil {
		return invalid("DATABASE_URL", "must be a valid PostgreSQL connection string; check the URI and password encoding")
	}
	for _, setting := range []struct {
		name     string
		min, max int64
	}{
		{"SERVER_PORT", 1, 65535}, {"BCRYPT_COST", 4, 31}, {"MAX_PAYLOAD_SIZE", 1, 1<<63 - 1},
	} {
		if value := os.Getenv(setting.name); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < setting.min || n > setting.max {
				return invalid(setting.name, fmt.Sprintf("must be an integer from %d to %d", setting.min, setting.max))
			}
		}
	}
	for _, name := range []string{"TOKEN_EXPIRY", "REQUEST_TIMEOUT"} {
		if value := os.Getenv(name); value != "" {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return invalid(name, "must be a positive Go duration, for example 30s or 24h")
			}
		}
	}
	for _, name := range []string{"CORS_ALLOW_ALL", "TRUST_PROXY_HEADERS"} {
		if value := os.Getenv(name); value != "" {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "1", "true", "yes", "y", "on", "0", "false", "no", "n", "off":
			default:
				return invalid(name, "must be a boolean, for example true or false")
			}
		}
	}
	if value := strings.ToLower(os.Getenv("LOG_LEVEL")); value != "" && value != "debug" && value != "info" && value != "warn" && value != "error" {
		return invalid("LOG_LEVEL", "must be debug, info, warn or error")
	}
	if value := strings.ToLower(os.Getenv("LOG_FORMAT")); value != "" && value != "json" && value != "text" {
		return invalid("LOG_FORMAT", "must be json or text")
	}
	email, password := strings.TrimSpace(os.Getenv("ADMIN_EMAIL")), os.Getenv("ADMIN_PASSWORD")
	if (email == "") != (password == "") {
		missing := "ADMIN_EMAIL"
		if password == "" {
			missing = "ADMIN_PASSWORD"
		}
		return &Error{Code: "ADMIN_CONFIGURATION_INCOMPLETE", Variable: missing, Message: "set both ADMIN_EMAIL and ADMIN_PASSWORD to seed an admin, or omit both to retain existing users"}
	}
	if len(password) > 72 {
		return invalid("ADMIN_PASSWORD", "must not exceed bcrypt's 72-byte password limit")
	}
	for _, name := range []string{"APPID_OAUTH_SERVER_URL", "APPID_REDIRECT_URI"} {
		if value := os.Getenv(name); value != "" {
			u, err := url.Parse(value)
			if err != nil || u.Scheme == "" || (u.Host == "" && u.Path == "") || u.User != nil || u.Fragment != "" {
				return invalid(name, "must be an absolute URL without user information or a fragment")
			}
			if name == "APPID_OAUTH_SERVER_URL" && (u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "") {
				return invalid(name, "must be an HTTP or HTTPS provider base URL without a query string")
			}
		}
	}
	return nil
}

// IncompleteSSOFields returns missing setting names only when SSO is partly configured.
func (c *Config) IncompleteSSOFields() []string {
	settings := []struct{ name, value string }{
		{"APPID_CLIENT_ID", c.AppIDClientID}, {"APPID_CLIENT_SECRET", c.AppIDClientSecret},
		{"APPID_OAUTH_SERVER_URL", c.AppIDOAuthServerURL}, {"APPID_REDIRECT_URI", c.AppIDRedirectURI},
	}
	var missing []string
	for _, setting := range settings {
		if setting.value == "" {
			missing = append(missing, setting.name)
		}
	}
	if len(missing) == len(settings) {
		return nil
	}
	return missing
}
