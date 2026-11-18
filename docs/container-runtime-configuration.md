# Container runtime configuration

The image contains application code and readable SQL migrations, not deployment
credentials. It runs as `app`, including when invoked as the migration service.
The server reads its process environment at startup. Values may come from an
ordinary Compose deployment or from variables supplied by Confidential Container
Runtime when starting the workload. Rebuilding the image is unnecessary when only
configuration values change.

In a raw environment section, contract variables belong below `env`:

```yaml
type: env
env:
  ADMIN_NAME: "Platform Admin"
  ADMIN_EMAIL: "admin@example.com"
  ADMIN_PASSWORD: "<deployment-specific password>"
  APPID_CLIENT_ID: "<registered client ID>"
  APPID_CLIENT_SECRET: "<registered client secret>"
  APPID_OAUTH_SERVER_URL: "https://identity.example/oauth"
  APPID_REDIRECT_URI: "https://application.example/callback"
```

Keep the deployment's existing logging, registry authentication and volume blocks.
The workload must explicitly pass the selected variables into the backend service;
the image cannot itself read another contract section. A name-only Compose
environment entry inherits that variable from the Compose process environment:

```yaml
environment:
  - ADMIN_NAME
  - ADMIN_EMAIL
  - ADMIN_PASSWORD
  - APPID_CLIENT_ID
  - APPID_CLIENT_SECRET
  - APPID_OAUTH_SERVER_URL
  - APPID_REDIRECT_URI
```

## Fallback behavior

- Existing deployments can continue supplying values directly through their
  Compose configuration. A missing contract section does not change that behavior.
- `SERVER_HOST`, `SERVER_PORT`, timeouts, logging and other optional settings retain
  their defaults from `internal/config/config.go` when absent or empty. An explicitly invalid value fails startup instead of silently using a default.
- SSO is disabled unless all four `APPID_*` settings are supplied. Local login
  remains available; no fallback SSO credential is embedded in the image.
- `ADMIN_NAME` defaults to `System Admin`. Missing `ADMIN_EMAIL` or `ADMIN_PASSWORD`
  skips admin seeding when both are absent. Supplying only one is a configuration error. Existing accounts are preserved, including their passwords.
  A fresh deployment must explicitly provide bootstrap credentials or provision
  users through its intended administrative process.
- `DATABASE_URL` remains mandatory. The server fails configuration loading if it
  is missing; there is no fallback database credential.

If a single Compose file must support both contract values and existing deployment
defaults, use Compose interpolation such as `${SERVER_PORT:-8080}`. Keep secret
fallbacks in private deployment inputs, never in the image. Do not resolve those
expressions on the developer machine when values should be supplied by the guest
runtime. The current Contract UI Compose importer rejects unresolved expressions;
use a prepared workload archive for that mode. A name-only inherited variable has
no inline fallback value.

Contract encryption protects delivery into the guest. After startup, normal
container environment-variable access rules apply; these are not Ultravisor
retrievable secrets.

## Diagnostic codes

Startup failures exit with status 1. Configuration failures use JSON logs with
`code`, `variable` and `hint`; neither passwords nor connection strings are logged.

| Code | Meaning / action |
|---|---|
| `CONFIG_REQUIRED` | Supply the named required variable. |
| `CONFIG_INVALID_VALUE` | Correct the named variable's format or range. |
| `ADMIN_CONFIGURATION_INCOMPLETE` | Set both bootstrap email and password, or omit both. |
| `SSO_CONFIGURATION_INCOMPLETE` | Warning: incomplete SSO is disabled; set all four `APPID_*` values. |
| `SSO_NOT_CONFIGURED` | HTTP 404 from an SSO endpoint while SSO is disabled; local login remains available. |
| `DATABASE_CONFIG_FAILED` | Correct the database connection configuration. |
| `DATABASE_CONNECT_FAILED` | Check database readiness, network, credentials and TLS. |
| `ADMIN_SEED_FAILED` | Apply database migrations and check bootstrap settings. |
| `SERVER_LISTEN_FAILED` | Check the listen address, port and port conflicts. |
| `SERVER_SHUTDOWN_FAILED` | Graceful shutdown did not finish. |
| `DATABASE_UNAVAILABLE` | HTTP 503 health response while the database is unavailable. |

A fully omitted SSO configuration is an expected fallback, not a startup error.
The Compose example leaves credentials empty and refuses to start services that
require them until deployment-specific values have been supplied.
