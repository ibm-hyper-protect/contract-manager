# Contract Generator

A secure, enterprise-grade contract generation system with role-based access control, cryptographic signing, and audit trails.

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- 2GB RAM minimum
- 5GB disk space

### Start the Application

```bash
# 1. Clone the repository
git clone <repository-url>
cd persona-based-contract-generator

# 2. Environment is already configured with .env file
# Review and customize passwords if needed:
nano .env

# 3. Start all services
docker compose up -d

# 4. Check service health
docker compose ps

# 5. Access the application
# Main App: http://localhost:8080
# PgAdmin: http://localhost:5050
# Vault UI: http://localhost:8000
```

### Default Credentials

**Admin Login:**
- Email: `admin@hpcr-builder.local`
- Password: `SecureAdminPassword123!` (change this!)

**PgAdmin:**
- Email: `admin@hpcr-builder.dev`
- Password: `SecurePgAdminPassword123!`

**Vault:**
- Token: `dev-root-token`

## Documentation

- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Complete deployment guide with production setup
- **[Design/](./Design/)** - Architecture and design documentation
- **[app/BUILD.md](./app/BUILD.md)** - Desktop application build instructions

## Architecture

### Services

| Service | Description | Port |
|---------|-------------|------|
| **reverse_proxy** | Nginx reverse proxy | 8080 (HTTP), 8443 (HTTPS) |
| **backend** | Go API server | Internal: 8080 |
| **postgres** | PostgreSQL 16 database | Internal: 5432 |
| **vault** | HashiCorp Vault for key management | 8200 |
| **pgadmin** | Database management UI | 5050 |
| **vault-ui** | Vault web interface | 8000 |

### Technology Stack

- **Backend**: Go 1.26+ with Chi router
- **Database**: PostgreSQL 16 with SQLC
- **Key Management**: HashiCorp Vault
- **Frontend**: React with Vite (Desktop app)
- **Containerization**: Docker & Docker Compose
- **Reverse Proxy**: Nginx

## Security Features

- **Role-Based Access Control (RBAC)** - Fine-grained permissions
- **Cryptographic Signing** - Contract integrity verification
- **Audit Trails** - Complete activity logging
- **Key Management** - Vault-based encryption key storage
- **Secure Communication** - TLS/HTTPS support
- **Password Security** - Bcrypt hashing with configurable cost
- **Token-Based Auth** - JWT with configurable expiry
- **Rate Limiting** - Protection against abuse
- **Security Headers** - CORS, CSP, and hardening middleware

## Features

### Contract Management
- Multi-section contract building
- Role-based section assignments
- Version control and tracking
- Contract finalization workflow
- Export to multiple formats

### User Management
- User registration and authentication
- Role assignment and management
- API token generation
- Credential rotation
- Activity monitoring

### Audit & Compliance
- Comprehensive audit logging
- System event tracking
- User activity monitoring
- Contract lifecycle tracking
- Export audit reports

### Key Management
- Vault-based key storage
- Automatic key rotation
- Public key management
- Signature verification
- Attestation support

## Development

### Project Structure

```
.
├── app/                    # Desktop application (Electron + React)
├── backend/               # Go backend API
│   ├── cmd/              # Application entrypoints
│   ├── internal/         # Internal packages
│   │   ├── handler/     # HTTP handlers
│   │   ├── service/     # Business logic
│   │   ├── repository/  # Database layer
│   │   ├── middleware/  # HTTP middleware
│   │   └── crypto/      # Cryptographic operations
│   └── migrations/       # Database migrations
├── config/               # Configuration files
│   └── nginx/           # Nginx configuration
├── Design/              # Architecture documentation
└── docker-compose.yaml  # Service orchestration
```

### Local Development

```bash
# Start services in development mode
docker compose up -d

# View logs
docker compose logs -f backend

# Run database migrations
docker compose restart migrate

# Access database
docker compose exec postgres psql -U hpcr hpcr_builder

# Rebuild backend after changes
docker compose up -d --build backend
```

### Running Tests

```bash
# Backend tests
cd backend
go test ./...

# With coverage
go test -cover ./...

# Integration tests
go test -tags=integration ./...
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Database
POSTGRES_PASSWORD=<secure-password>
DATABASE_URL=postgres://...

# Admin User
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=<secure-password>

# Security
TOKEN_EXPIRY=24h
BCRYPT_COST=12

# Vault
VAULT_TOKEN=<vault-token>
VAULT_ADDR=http://vault:8200
```

See [.env.example](./.env.example) for all available options.

### Production Deployment

For production deployment:

1. **Update passwords** - Change all default passwords
2. **Enable TLS** - Configure SSL certificates
3. **Configure Vault** - Use production Vault setup
4. **Set CORS** - Update allowed origins
5. **Enable monitoring** - Set up logging and alerts

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed instructions.

## Monitoring

### Health Checks

```bash
# Backend health
curl http://localhost:8080/health

# Nginx health
curl http://localhost:8080/nginx-health

# Vault health
curl http://localhost:8200/v1/sys/health

# All services
docker compose ps
```

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend

# Last 100 lines
docker compose logs --tail=100 backend
```

## Troubleshooting

### Common Issues

**Services won't start:**
```bash
docker compose down
docker compose up -d
docker compose logs
```

**Database connection errors:**
```bash
docker compose exec postgres pg_isready -U hpcr
docker compose restart backend
```

**Permission errors:**
```bash
sudo chown -R 1000:1000 data/postgres
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for more troubleshooting tips.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[Add your license information here]

## Support

For issues or questions:
- Check the [DEPLOYMENT.md](./DEPLOYMENT.md) guide
- Review existing GitHub issues
- Create a new issue with details
- Contact the development team

## Version History

- **v1.0.0** - Initial release with core features
  - Contract management
  - User authentication
  - Role-based access control
  - Vault integration
  - Audit logging

## Acknowledgments

- HashiCorp Vault for key management
- PostgreSQL for reliable data storage
- Go community for excellent libraries
- Docker for containerization

---

**Note**: This is a development setup. For production deployment, follow the security guidelines in [DEPLOYMENT.md](./DEPLOYMENT.md).
