targetScope = 'resourceGroup'

@description('Azure region for the Proof of Concept resources.')
param location string = resourceGroup().location

@description('Short lowercase name used in globally unique resource names.')
@minLength(3)
@maxLength(18)
param resourcePrefix string

@description('Object ID of the App Registration service principal authorized to ingest.')
@minLength(36)
@maxLength(36)
param ingestionPrincipalId string

@description('Tags applied to every resource.')
param tags object = {}

var uniqueSuffix = uniqueString(
  subscription().subscriptionId,
  resourceGroup().id,
  resourcePrefix,
  'poc'
)
var effectiveTags = union(tags, {
  solution: 'intune-deployment-telemetry'
  environment: 'poc'
  managedBy: 'bicep'
})

module observability 'modules/observability.bicep' = {
  name: 'poc-observability-${uniqueSuffix}'
  params: {
    location: location
    resourcePrefix: resourcePrefix
    uniqueSuffix: uniqueSuffix
    retentionInDays: 30
    dailyCapGb: 1
    deployApplicationInsights: false
    deployDataCollectionEndpoint: false
    ingestionPrincipalId: ingestionPrincipalId
    tags: effectiveTags
  }
}

output workspaceName string = observability.outputs.workspaceName
output customTableName string = observability.outputs.tableName
output dataCollectionRuleName string = observability.outputs.dcrName
output logsIngestionEndpoint string = observability.outputs.logsIngestionEndpoint
output dcrImmutableId string = observability.outputs.dcrImmutableId
output deploymentSku string = 'poc'
