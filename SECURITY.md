<!--
Copyright (c) 2025 IBM Corp.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

We recommend always using the latest release to ensure you have the latest security updates.

## Reporting a Vulnerability

The `contract-manager` team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### Please DO NOT:

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

### Instead, Please:

**Report security vulnerabilities via GitHub Security Advisories:**

1. Go to the [Security tab](https://github.com/ibm-hyper-protect/contract-manager/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the form with details about the vulnerability

**Or, report via email:**

Contact the Security maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) directly with details about the vulnerability.

### What to Include in Your Report

To help us understand and address the issue quickly, please include:

- **Description** — A clear description of the vulnerability
- **Impact** — What an attacker could achieve by exploiting this vulnerability
- **Reproduction Steps** — Detailed steps to reproduce the issue
- **Affected Versions** — Which versions of the project are affected
- **Proposed Fix** — If you have suggestions for how to fix the issue (optional)
- **Your Contact Information** — So we can follow up with questions

### What to Expect

When you report a security vulnerability, here's what will happen:

1. **Acknowledgment** — We will acknowledge receipt of your vulnerability report within 3 business days
2. **Initial Assessment** — We will investigate and confirm the vulnerability within 5 business days
3. **Updates** — We will keep you informed about our progress addressing the issue
4. **Fix Development** — We will develop and test a fix for the vulnerability
5. **Release** — We will:
   - Release a patched version
   - Publish a security advisory
   - Credit you for the discovery (unless you prefer to remain anonymous)

### Timeline

We aim to:

- Acknowledge reports within **3 business days**
- Provide an initial assessment within **5 business days**
- Release a fix within **30 days** for high-severity issues
- Release a fix within **90 days** for medium/low-severity issues

These timelines may vary depending on the complexity of the issue.

## Security Best Practices

When deploying or using `contract-manager`, we recommend the following:

### For Operators

1. **Keep Everything Updated**
   - Regularly update to the latest version of `contract-manager`
   - Keep Docker images, Go dependencies, and PostgreSQL up to date
   - Monitor security advisories for this project and its dependencies

2. **Protect Sensitive Data**
   - Never commit private keys, certificates, or credentials to version control
   - Use environment variables or a secure vault (e.g., HashiCorp Vault) for sensitive configuration
   - Rotate credentials and tokens regularly

3. **Secure the Database**
   - Use strong, unique passwords for PostgreSQL
   - Restrict network access to the database port
   - Enable TLS for database connections in production

4. **Vault Configuration**
   - Do not use `dev-root-token` in production — initialize and unseal Vault properly
   - Enable audit logging on Vault
   - Rotate Vault tokens and keys according to your security policy

5. **Network Security**
   - Enable HTTPS/TLS — see [DEPLOYMENT.md](DEPLOYMENT.md) for TLS configuration
   - Do not bind services to `0.0.0.0` in production without firewall rules
   - Use the reverse proxy to terminate TLS and enforce security headers

6. **Authentication**
   - Change all default passwords before going to production
   - Set an appropriate `TOKEN_EXPIRY` value for your use case
   - Configure `BCRYPT_COST` to at least `12`

7. **Container Security**
   - Run containers as non-root users (already configured)
   - Regularly rebuild images to pull in base image security patches
   - Use read-only root filesystems where possible

### For Contributors

1. **Code Review**
   - All code changes require review before merging
   - Pay special attention to authentication, authorization, and cryptographic operations
   - Use parameterized queries for all database operations — never string interpolation

2. **Dependency Management**
   - Regularly audit dependencies for known vulnerabilities
   - Keep Go modules up to date
   - Review dependency updates before merging

3. **Testing**
   - Write tests that cover security-relevant code paths
   - Test error handling and edge cases
   - Never use real credentials in test code — use mock data and test fixtures

4. **Secrets in Tests**
   - Never commit real credentials, tokens, or keys
   - Use clearly fake placeholder values in examples and tests

## Known Security Considerations

### Authentication and Authorization

This project implements:

- **JWT-based authentication** — Tokens are signed and verified on every request
- **Role-Based Access Control (RBAC)** — Fine-grained permissions enforced at the handler level
- **Bcrypt password hashing** — With configurable cost factor
- **Token expiry** — Configurable session lifetime

### Cryptographic Operations

This project performs cryptographic operations including:

- **Cryptographic contract signing** — Using asymmetric keys for contract integrity
- **Key management via Vault** — HashiCorp Vault stores and manages encryption keys
- **Bcrypt hashing** — For password storage
- **SHA-256** — For integrity checksums

These operations rely on:
- Proper HashiCorp Vault initialization and configuration
- Secure key generation and storage
- A trusted TLS certificate for HTTPS in production

### Audit Trails

The system maintains a comprehensive audit log of all operations including:
- User authentication events
- Contract lifecycle changes
- Role assignment changes
- Key management operations

Ensure audit logs are protected from unauthorized modification and retained according to your compliance policy.

## Vulnerability Disclosure Policy

We believe in coordinated vulnerability disclosure:

1. **Report** — Security researchers report vulnerabilities privately
2. **Fix** — We develop and test a fix
3. **Release** — We release the patched version
4. **Disclose** — We publish a security advisory with credit to the researcher
5. **Public** — Full details are disclosed after users have time to update

We will not take legal action against security researchers who:
- Make a good faith effort to avoid privacy violations and data destruction
- Report vulnerabilities privately and give us reasonable time to respond
- Do not exploit vulnerabilities beyond what's necessary to demonstrate the issue

## Security Updates

Stay informed about security updates:

- **GitHub Security Advisories** — Watch this repository for security advisories
- **Releases** — Check the [Releases page](https://github.com/ibm-hyper-protect/contract-manager/releases) for security patches
- **Changelog** — Review `CHANGELOG.md` for security-related changes

## Questions?

If you have questions about this security policy or the security of this project:

1. Review this document thoroughly
2. Check existing [security advisories](https://github.com/ibm-hyper-protect/contract-manager/security/advisories)
3. Contact the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md)

---

Thank you for helping keep `contract-manager` and our users safe!
