using '../poc.bicep'

param resourcePrefix = 'intunetlm'
param ingestionPrincipalId = readEnvironmentVariable('INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID', '')
param tags = {
  workload: 'endpoint-telemetry'
  criticality: 'proof-of-concept'
}
