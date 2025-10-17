# EQLoginOIDC Kubernetes Deployment

This directory contains Kubernetes deployment configurations for the EQLoginOIDC application using Kustomize and FluxCD.

## Directory Structure

```
deployments/
├── overlay/
│   ├── base/                    # Base Kustomize configuration
│   │   ├── kustomize.yaml      # Base kustomization
│   │   ├── deployment.yaml     # Deployment manifest
│   │   ├── service.yaml        # Service manifest
│   │   ├── configmap.yaml      # Configuration data
│   │   └── secret.yaml         # Secrets (DB credentials, TLS certs)
│   ├── production/             # Production overlay
│   │   ├── kustomize.yaml      # Production kustomization
│   │   └── deployment-patch.yaml # Production-specific patches
│   └── staging/                # Staging overlay
│       ├── kustomize.yaml      # Staging kustomization
│       └── deployment-patch.yaml # Staging-specific patches
├── flux-kustomization.yaml     # FluxCD Kustomization resources
└── README.md                   # This file
```

## Prerequisites

1. **MySQL Database**: The application requires a MySQL database. Ensure you have:
   - A MySQL instance accessible from your Kubernetes cluster
   - Database credentials configured in secrets
   - The `quarm` database created

2. **TLS Certificates**: The application requires TLS certificates for HTTPS:
   - Certificate and private key must be provided in the `eqloginoidc-tls` secret
   - Certificates should be valid for your domain

3. **Docker Image**: Build and push your Docker image to a registry accessible by your cluster:
   ```bash
   docker build -t your-registry/eqloginoidc:latest .
   docker push your-registry/eqloginoidc:latest
   ```

## Configuration

### Environment Variables

The application uses the following environment variables:

- `DB_HOST`: Database host (default: localhost)
- `DB_PORT`: Database port (default: 3306)
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_NAME`: Database name (default: quarm)
- `CLIENT_CONFIG`: Path to client configuration file (default: clients.yaml)
- `CERT_FILE`: Path to certificate file (default: cert.pem)
- `KEY_FILE`: Path to private key file (default: key.pem)

### Client Configuration

The `clients.yaml` file in the ConfigMap defines OIDC clients. Example configuration:

```yaml
clients:
  - id: "example-client"
    name: "Example OIDC Client"
    client_type: "confidential"
    secret: "your-client-secret-here"
    redirect_uris:
      - "https://localhost:3000/callback"
    grant_types:
      - "authorization_code"
    response_types:
      - "code"
    scopes:
      - "openid"
      - "profile"
    require_https: true
    pkce_required: false
```

## Customization

### Adding New Environments

To add a new environment (e.g., development):

1. Create a new overlay directory: `deployments/overlay/development/`
2. Create `kustomize.yaml` and any necessary patches
3. Add a corresponding FluxCD Kustomization in `flux-kustomization.yaml`

### Security Considerations

- **Secrets**: Store sensitive data (DB passwords, TLS keys) in Kubernetes secrets
- **Network Policies**: Consider implementing network policies for additional security
- **RBAC**: Ensure proper RBAC configuration for service accounts
- **Pod Security**: The deployment uses non-root user and read-only root filesystem

## Monitoring

The deployment includes:

- **Liveness probes**: HTTP GET on `/` endpoint
- **Readiness probes**: HTTP GET on `/` endpoint
- **Health checks**: FluxCD health checks for deployment status

## Troubleshooting

1. **Check pod logs**:
   ```bash
   kubectl logs -l app=eqloginoidc -n eqloginoidc-prod
   ```

2. **Verify configuration**:
   ```bash
   kubectl describe configmap eqloginoidc-config -n eqloginoidc-prod
   kubectl describe secret eqloginoidc-secrets -n eqloginoidc-prod
   ```

3. **Check FluxCD status**:
   ```bash
   kubectl get kustomizations -n flux-system
   kubectl describe kustomization eqloginoidc-production -n flux-system
   ```

## OIDC Endpoints

The application exposes the following OIDC endpoints:

- `/.well-known/openid-configuration` - OIDC Discovery
- `/.well-known/jwks.json` - JSON Web Key Set
- `/auth` - Authorization endpoint
- `/token` - Token endpoint
- `/userinfo` - UserInfo endpoint
- `/login` - Login page
- `/` - Home page



