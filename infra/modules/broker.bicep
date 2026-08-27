@description('Azure region.')
param location string

@minLength(3)
param resourcePrefix string
@minLength(3)
@maxLength(22)
param uniqueSuffix string
param solutionSku string
param functionPlanName string
param functionPlanTier string
param functionCapacity int
param minimumElasticWorkers int
param maximumScaleOutLimit int
param zoneRedundant bool
param appConfigurationSku string
param applicationInsightsConnectionString string
param logsIngestionEndpoint string
param dcrImmutableId string
param dcrResourceId string
param dcrName string

@secure()
param trustedClientRootsBase64 string

param trustedIssuerCaSha256Thumbprints string

param tags object

var functionAppName = 'func-${resourcePrefix}-${uniqueSuffix}'
var planName = 'asp-${resourcePrefix}-${uniqueSuffix}'
var storageName = 'st${uniqueSuffix}'
var appConfigurationName = 'appcs-${resourcePrefix}-${uniqueSuffix}'
var keyVaultName = 'kv-${uniqueSuffix}'
var appConfigurationKeyPrefix = 'IntuneTelemetry:'
var trustedRootsSecretName = 'client-certificate-trusted-roots'
var monitoringMetricsPublisherRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '3913510d-42f4-4e42-8a64-420c390055eb'
)
var storageBlobDataOwnerRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
)
var storageQueueDataContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
)
var storageTableDataContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)
var appConfigurationDataReaderRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '516239f1-63e1-4d78-a4de-a74fb236a071'
)
var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

resource appConfiguration 'Microsoft.AppConfiguration/configurationStores@2024-05-01' = {
  name: appConfigurationName
  location: location
  tags: tags
  sku: {
    name: appConfigurationSku
  }
  properties: {
    disableLocalAuth: true
    enablePurgeProtection: solutionSku != 'dev'
    publicNetworkAccess: 'Enabled'
    softDeleteRetentionInDays: solutionSku == 'dev' ? 1 : 30
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
    enablePurgeProtection: solutionSku != 'dev'
    enableSoftDelete: true
    publicNetworkAccess: 'Enabled'
    softDeleteRetentionInDays: solutionSku == 'dev' ? 7 : 90
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

resource trustedRootsSecret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: trustedRootsSecretName
  properties: {
    value: trustedClientRootsBase64
  }
}

resource logsEndpointSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}LOGS_INGESTION_ENDPOINT'
  properties: {
    value: logsIngestionEndpoint
  }
}

resource dcrIdSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}LOGS_DCR_IMMUTABLE_ID'
  properties: {
    value: dcrImmutableId
  }
}

resource streamNameSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}LOGS_STREAM_NAME'
  properties: {
    value: 'Custom-IntuneDeploymentTelemetry'
  }
}

resource issuerFingerprintsSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS'
  properties: {
    value: trustedIssuerCaSha256Thumbprints
  }
}

resource bodyLimitSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}TELEMETRY_MAX_BODY_BYTES'
  properties: {
    value: '131072'
  }
}

resource trustedRootsSetting 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = {
  parent: appConfiguration
  name: '${appConfigurationKeyPrefix}CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64'
  properties: {
    value: '{"uri":"${keyVault.properties.vaultUri}secrets/${trustedRootsSecret.name}"}'
    contentType: 'application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: planName
  location: location
  kind: 'linux'
  tags: tags
  sku: {
    name: functionPlanName
    tier: functionPlanTier
    capacity: functionCapacity
  }
  properties: {
    reserved: true
    zoneRedundant: zoneRedundant
    maximumElasticWorkerCount: maximumScaleOutLimit
  }
}

resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  tags: union(tags, {
    'azd-service-name': 'broker'
  })
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientCertEnabled: true
    clientCertMode: 'Required'
    clientCertExclusionPaths: '/api/health'
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      alwaysOn: solutionSku != 'dev'
      ftpsState: 'Disabled'
      http20Enabled: true
      linuxFxVersion: 'DOTNET-ISOLATED|10.0'
      minTlsVersion: '1.2'
      minimumElasticInstanceCount: minimumElasticWorkers
      preWarmedInstanceCount: minimumElasticWorkers
      use32BitWorkerProcess: false
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'dotnet-isolated'
        }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storage.name
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsightsConnectionString
        }
        {
          name: 'AZURE_APPCONFIG_ENDPOINT'
          value: appConfiguration.properties.endpoint
        }
      ]
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' existing = {
  name: dcrName
}

resource dcrPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcrResourceId, functionApp.id, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: monitoringMetricsPublisherRoleId
  }
}

resource storageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageBlobDataOwnerRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataOwnerRoleId
  }
}

resource storageQueueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageQueueDataContributorRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageQueueDataContributorRoleId
  }
}

resource storageTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, functionApp.id, storageTableDataContributorRoleId)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleId
  }
}

resource appConfigurationReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfiguration.id, functionApp.id, appConfigurationDataReaderRoleId)
  scope: appConfiguration
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: appConfigurationDataReaderRoleId
  }
}

resource keyVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

output functionAppName string = functionApp.name
output defaultHostname string = functionApp.properties.defaultHostName
output appConfigurationName string = appConfiguration.name
output keyVaultName string = keyVault.name
