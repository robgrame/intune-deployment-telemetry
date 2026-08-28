# ☁️ Azure deployment

## Prerequisites

- Contributor permissions on the target resource group
- User Access Administrator or equivalent role-assignment permissions
- Azure CLI and Bicep
- public trusted-root CA certificate in DER format

## Validate infrastructure

```powershell
az bicep build --file .\infra\main.bicep
az bicep build --file .\infra\poc.bicep

az deployment group what-if `
  --resource-group <resource-group> `
  --template-file .\infra\main.bicep `
  --parameters .\infra\environments\prod.bicepparam
```

## Deploy

Use the deployment script for every profile:

```powershell
.\scripts\deployment\Deploy-IntuneTelemetry.ps1 `
  -DeploymentType prod `
  -ResourceGroupName <resource-group> `
  -TrustedRootCertificatePaths C:\certificates\IntuneTelemetryRoot.cer `
  -TrustedIssuerCaSha256Thumbprints '<64-character-SHA256-fingerprint>'
```

For a short-lived constrained pilot, create the dedicated App Registration
and service principal first. Add a short-lived client secret to the App
Registration, then expose its **service principal object ID** to Bicep:

```powershell
.\scripts\deployment\Deploy-IntuneTelemetry.ps1 `
  -DeploymentType poc `
  -ResourceGroupName <resource-group> `
  -PocServicePrincipalObjectId '<SERVICE-PRINCIPAL-OBJECT-ID>'
```

The Proof of Concept (`poc`) profile creates only the workspace, custom table,
direct DCR, and DCR-scoped role assignment. If the object ID is missing, the
The service principal object ID is mandatory for `poc`; the script stops
before deployment if it isn't supplied.

The Bicep deployment never receives or stores the client secret. Configure it
only in the signed Intune Platform Script and revoke it immediately when the
experiment ends.

Use `-WhatIfOnly` to validate and preview any profile without changing Azure.
Use `-Subscription` when the active Azure CLI subscription isn't the intended
target.

The `dev`, `prod`, and `premium` deployments output the broker hostname,
health URL, App Configuration store, and Key Vault. They create
`IntuneTelemetry:*` settings, store the trusted-root bundle in Key Vault, and
connect it with an App Configuration Key Vault reference.

The `poc` deployment outputs the workspace, custom table, DCR name, direct
logs-ingestion endpoint, and immutable DCR ID required by the endpoint script.

Pass multiple paths to `TrustedRootCertificatePaths` during CA rotation so the
current and next roots overlap safely.

Deploy application code only after the managed-identity role assignments have
propagated. No App Configuration access key, Key Vault secret value, or Azure
Monitor credential is placed in Function App settings.

## CI/CD authentication

Use GitHub Actions OpenID Connect federation. Do not create a long-lived Azure
client secret. Scope the deployment identity to the target resource group and
grant role-assignment permissions only when the workflow owns RBAC deployment.

## Direct-ingestion experiment

For the minimal direct-ingestion profile, follow the
[Proof of Concept direct-ingestion plan](poc-direct-ingestion.md). Do not use
the legacy HTTP Data Collector API or distribute a Log Analytics workspace
shared key.
