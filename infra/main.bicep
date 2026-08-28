targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short lowercase name used in globally unique resource names.')
@minLength(3)
@maxLength(18)
param resourcePrefix string

@allowed([
  'dev'
  'prod'
  'premium'
])
@description('Solution deployment profile.')
param solutionSku string

@description('Base64 DER encoded trusted root CA certificates, separated by semicolons.')
@secure()
param trustedClientRootsBase64 string

@description('SHA-256 fingerprints of authorized immediate issuing CA certificates, separated by semicolons.')
param trustedIssuerCaSha256Thumbprints string

@description('Tags applied to every resource.')
param tags object = {}

var profiles = {
  dev: {
    functionPlanName: 'Y1'
    functionPlanTier: 'Dynamic'
    functionCapacity: 0
    minimumElasticWorkers: 0
    maximumScaleOutLimit: 10
    zoneRedundant: false
    workspaceRetentionDays: 30
    workspaceDailyCapGb: 1
    appConfigurationSku: 'free'
  }
  prod: {
    functionPlanName: 'EP1'
    functionPlanTier: 'ElasticPremium'
    functionCapacity: 1
    minimumElasticWorkers: 1
    maximumScaleOutLimit: 20
    zoneRedundant: false
    workspaceRetentionDays: 90
    workspaceDailyCapGb: 20
    appConfigurationSku: 'standard'
  }
  premium: {
    functionPlanName: 'EP2'
    functionPlanTier: 'ElasticPremium'
    functionCapacity: 2
    minimumElasticWorkers: 2
    maximumScaleOutLimit: 50
    zoneRedundant: true
    workspaceRetentionDays: 365
    workspaceDailyCapGb: 100
    appConfigurationSku: 'standard'
  }
}

var profile = profiles[solutionSku]
var uniqueSuffix = uniqueString(subscription().subscriptionId, resourceGroup().id, resourcePrefix, solutionSku)
var effectiveTags = union(tags, {
  solution: 'intune-deployment-telemetry'
  environment: solutionSku
  managedBy: 'bicep'
})

module observability 'modules/observability.bicep' = {
  name: 'observability-${uniqueSuffix}'
  params: {
    location: location
    resourcePrefix: resourcePrefix
    uniqueSuffix: uniqueSuffix
    retentionInDays: profile.workspaceRetentionDays
    dailyCapGb: profile.workspaceDailyCapGb
    tags: effectiveTags
  }
}

module broker 'modules/broker.bicep' = {
  name: 'broker-${uniqueSuffix}'
  params: {
    location: location
    resourcePrefix: resourcePrefix
    uniqueSuffix: uniqueSuffix
    solutionSku: solutionSku
    functionPlanName: profile.functionPlanName
    functionPlanTier: profile.functionPlanTier
    functionCapacity: profile.functionCapacity
    minimumElasticWorkers: profile.minimumElasticWorkers
    maximumScaleOutLimit: profile.maximumScaleOutLimit
    zoneRedundant: profile.zoneRedundant
    appConfigurationSku: profile.appConfigurationSku
    applicationInsightsConnectionString: observability.outputs.applicationInsightsConnectionString
    logsIngestionEndpoint: observability.outputs.logsIngestionEndpoint
    dcrImmutableId: observability.outputs.dcrImmutableId
    dcrResourceId: observability.outputs.dcrResourceId
    dcrName: observability.outputs.dcrName
    trustedClientRootsBase64: trustedClientRootsBase64
    trustedIssuerCaSha256Thumbprints: trustedIssuerCaSha256Thumbprints
    tags: effectiveTags
  }
}

output brokerHostname string = broker.outputs.defaultHostname
output brokerHealthUrl string = 'https://${broker.outputs.defaultHostname}/api/health'
output functionAppName string = broker.outputs.functionAppName
output workspaceName string = observability.outputs.workspaceName
output customTableName string = observability.outputs.tableName
output dataCollectionRuleName string = observability.outputs.dcrName
output workbookName string = observability.outputs.workbookName
output workbookResourceId string = observability.outputs.workbookResourceId
output appConfigurationName string = broker.outputs.appConfigurationName
output keyVaultName string = broker.outputs.keyVaultName
output deploymentSku string = solutionSku
