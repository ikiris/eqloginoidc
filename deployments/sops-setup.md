# SOPS Setup Guide for EQLoginOIDC

This guide explains how to set up and use SOPS (Secrets OPerationS) to encrypt sensitive data in your Kubernetes manifests.

## Prerequisites

1. **Install SOPS**:
   ```bash
   # macOS
   brew install sops
   
   # Linux
   curl -LO https://github.com/mozilla/sops/releases/latest/download/sops-v3.8.1.linux
   chmod +x sops-v3.8.1.linux
   sudo mv sops-v3.8.1.linux /usr/local/bin/sops
   
   # Windows
   choco install sops
   ```

2. **Generate or Import PGP Key**:
   ```bash
   # Generate new PGP key
   gpg --full-generate-key
   
   # List your keys to get the fingerprint
   gpg --list-secret-keys --keyid-format=long
   ```

## Configuration

### 1. Update SOPS Configuration

Edit the `.sops.yaml` files in each overlay directory and replace `YOUR_PGP_FINGERPRINT_HERE` with your actual PGP fingerprint:

```yaml
creation_rules:
  - path_regex: \.yaml$
    pgp: >-
      YOUR_ACTUAL_PGP_FINGERPRINT
    unencrypted_suffix: _unencrypted
```

### 2. Update Secret Files

Edit the `secret.enc.yaml` files in each overlay directory with your actual values:

**Base (`deployments/overlay/base/secret.enc.yaml`)**:
```yaml
stringData:
  db-user: your_actual_db_user
  db-password: your_actual_db_password
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    YOUR_ACTUAL_CERTIFICATE_CONTENT
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    YOUR_ACTUAL_PRIVATE_KEY_CONTENT
    -----END PRIVATE KEY-----
```

**Production (`deployments/overlay/production/secret.enc.yaml`)**:
```yaml
stringData:
  db-user: your_prod_db_user
  db-password: your_secure_prod_password
  # ... TLS certificates for production
```

**Staging (`deployments/overlay/staging/secret.enc.yaml`)**:
```yaml
stringData:
  db-user: your_staging_db_user
  db-password: your_staging_password
  # ... TLS certificates for staging
```

## Encryption Process

### 1. Encrypt the Secret Files

```bash
# Encrypt base secrets
cd deployments/overlay/base
sops -e -i secret.enc.yaml

# Encrypt production secrets
cd ../production
sops -e -i secret.enc.yaml

# Encrypt staging secrets
cd ../staging
sops -e -i secret.enc.yaml
```

### 2. Verify Encryption

After encryption, the files should contain encrypted content that looks like:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: eqloginoidc-secrets
  labels:
    app: eqloginoidc
    component: oidc-provider
type: Opaque
stringData:
  db-user: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
  db-password: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  kms: []
  gcp_kms: []
  azure_kv: []
  hc_vault: []
  age: []
  lastmodified: "2024-01-01T00:00:00Z"
  mac: "..."
  pgp:
    - created_at: "2024-01-01T00:00:00Z"
      enc: |
        -----BEGIN PGP MESSAGE-----
        ...
        -----END PGP MESSAGE-----
      fp: YOUR_PGP_FINGERPRINT
  unencrypted_suffix: _unencrypted
  version: 3.8.1
```

## Usage with Kustomize

### 1. Local Development

```bash
# Build with SOPS decryption
kustomize build --enable-alpha-plugins deployments/overlay/staging

# Apply with SOPS decryption
kustomize build --enable-alpha-plugins deployments/overlay/staging | kubectl apply -f -
```

### 2. FluxCD Integration

FluxCD supports SOPS out of the box. Make sure you have the SOPS secret configured in your FluxCD namespace:

```bash
# Create SOPS secret for FluxCD
kubectl create secret generic sops-gpg \
  --from-file=private.key=<(gpg --export-secret-keys --armor YOUR_PGP_FINGERPRINT) \
  --namespace=flux-system

# Annotate the secret
kubectl annotate secret sops-gpg \
  --namespace=flux-system \
  kustomize.toolkit.fluxcd.io/decryption-provider=sops \
  kustomize.toolkit.fluxcd.io/decryption-secret=sops-gpg
```

## Security Best Practices

1. **Key Management**:
   - Use separate PGP keys for different environments
   - Store PGP private keys securely (e.g., in a password manager)
   - Rotate keys regularly

2. **Access Control**:
   - Limit who has access to the PGP private key
   - Use different keys for different teams/environments
   - Consider using age encryption for better performance

3. **Backup**:
   - Keep encrypted backups of your secret files
   - Store PGP keys in multiple secure locations
   - Document the key rotation process

## Troubleshooting

### Common Issues

1. **"No PGP key found"**:
   - Ensure your PGP key is imported: `gpg --import your-key.asc`
   - Check the fingerprint in `.sops.yaml` matches your key

2. **"Failed to decrypt"**:
   - Verify the PGP key is available: `gpg --list-secret-keys`
   - Check if the key is expired or revoked

3. **FluxCD not decrypting**:
   - Ensure the SOPS secret is properly configured in flux-system namespace
   - Check FluxCD logs for decryption errors

### Useful Commands

```bash
# Decrypt and view a file
sops -d secret.enc.yaml

# Edit an encrypted file
sops secret.enc.yaml

# Check if a file is encrypted
sops -d secret.enc.yaml > /dev/null && echo "Encrypted" || echo "Not encrypted"

# List all encrypted files
find . -name "*.enc.yaml" -exec sops -d {} \; > /dev/null 2>&1 && echo "All encrypted" || echo "Some files not encrypted"
```

## File Structure

```
deployments/
├── overlay/
│   ├── base/
│   │   ├── .sops.yaml          # SOPS configuration
│   │   ├── secret.enc.yaml     # Encrypted base secrets
│   │   └── secret.yaml         # Unencrypted template (remove after encryption)
│   ├── production/
│   │   ├── .sops.yaml          # SOPS configuration
│   │   └── secret.enc.yaml     # Encrypted production secrets
│   └── staging/
│       ├── .sops.yaml          # SOPS configuration
│       └── secret.enc.yaml     # Encrypted staging secrets
└── sops-setup.md               # This guide
```

Remember to remove the unencrypted `secret.yaml` files after encryption for security!



