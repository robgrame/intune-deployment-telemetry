using '../main.bicep'

param resourcePrefix = 'intunetlm'
param solutionSku = 'dev'
param trustedClientRootsBase64 = readEnvironmentVariable('INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64', '')
param trustedIssuerCaSha256Thumbprints = readEnvironmentVariable('INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS', '')
param tags = {
  workload: 'endpoint-telemetry'
  criticality: 'development'
}
