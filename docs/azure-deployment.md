# ☁️ Azure deployment

## Prerequisites

- Contributor permissions on the target resource group
- User Access Administrator or equivalent role-assignment permissions
- Azure CLI and Bicep
- public trusted-root CA certificate in DER format

## Validate infrastructure

```powershell
az bicep build --file .\infra\main.bicep

az deployment group what-if `
  --resource-group <resource-group> `
  --template-file .\infra\main.bicep `
  --parameters .\infra\environments\prod.bicepparam
```

## Deploy

```powershell
$env:INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64 = `
  [Convert]::ToBase64String(
    [IO.File]::ReadAllBytes('C:\certificates\IntuneTelemetryRoot.cer')
  )
$env:INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS = `
  '<64-character-SHA256-fingerprint>'

az deployment group create `
  --resource-group <resource-group> `
  --template-file .\infra\main.bicep `
  --parameters .\infra\environments\prod.bicepparam
```

The deployment outputs the broker hostname, health URL, App Configuration
store, and Key Vault. It creates `IntuneTelemetry:*` settings, stores the
trusted-root bundle in Key Vault, and connects it with an App Configuration
Key Vault reference.

Deploy application code only after the managed-identity role assignments have
propagated. No App Configuration access key, Key Vault secret value, or Azure
Monitor credential is placed in Function App settings.

## CI/CD authentication

Use GitHub Actions OpenID Connect federation. Do not create a long-lived Azure
client secret. Scope the deployment identity to the target resource group and
grant role-assignment permissions only when the workflow owns RBAC deployment.
