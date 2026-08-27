@description('Azure region.')
param location string

@description('Resource naming prefix.')
param resourcePrefix string

@description('Deterministic uniqueness suffix.')
param uniqueSuffix string

@description('Log Analytics retention in days.')
param retentionInDays int

@description('Log Analytics daily ingestion cap in GB.')
param dailyCapGb int

param tags object

var workspaceName = 'law-${resourcePrefix}-${uniqueSuffix}'
var applicationInsightsName = 'appi-${resourcePrefix}-${uniqueSuffix}'
var dceName = 'dce-${resourcePrefix}-${uniqueSuffix}'
var dcrName = 'dcr-${resourcePrefix}-${uniqueSuffix}'
var tableName = 'IntuneDeploymentTelemetry_CL'
var streamName = 'Custom-IntuneDeploymentTelemetry'
var telemetryColumns = [
  {
    name: 'TimestampUtc'
    type: 'datetime'
  }
  {
    name: 'BrokerReceivedTimestampUtc'
    type: 'datetime'
  }
  {
    name: 'BrokerRequestId'
    type: 'string'
  }
  {
    name: 'ClientCertificateThumbprint'
    type: 'string'
  }
  {
    name: 'ClientCertificateIssuerThumbprint'
    type: 'string'
  }
  {
    name: 'DeviceName'
    type: 'string'
  }
  {
    name: 'DeviceId'
    type: 'string'
  }
  {
    name: 'AzureAdDeviceId'
    type: 'string'
  }
  {
    name: 'ManagedDeviceId'
    type: 'string'
  }
  {
    name: 'TenantDirectoryId'
    type: 'string'
  }
  {
    name: 'UserUPN'
    type: 'string'
  }
  {
    name: 'CurrentLoggedOnUser'
    type: 'string'
  }
  {
    name: 'FirstExecutionTimestampUtc'
    type: 'datetime'
  }
  {
    name: 'CurrentExecutionTimestampUtc'
    type: 'datetime'
  }
  {
    name: 'AssignmentTimestampUtc'
    type: 'datetime'
  }
  {
    name: 'AssignmentToExecutionMinutes'
    type: 'real'
  }
  {
    name: 'LastBootTimeUtc'
    type: 'datetime'
  }
  {
    name: 'UptimeHours'
    type: 'real'
  }
  {
    name: 'OSVersion'
    type: 'string'
  }
  {
    name: 'BuildNumber'
    type: 'string'
  }
  {
    name: 'RestartPending'
    type: 'boolean'
  }
  {
    name: 'RestartPendingReasons'
    type: 'dynamic'
  }
  {
    name: 'MDMEnrollmentStatus'
    type: 'string'
  }
  {
    name: 'MDMEnrollmentDateUtc'
    type: 'datetime'
  }
  {
    name: 'MDMProviderId'
    type: 'string'
  }
  {
    name: 'MDMEnrollmentType'
    type: 'string'
  }
  {
    name: 'MDMEnrollmentState'
    type: 'string'
  }
  {
    name: 'LastKnownMDMSync'
    type: 'datetime'
  }
  {
    name: 'EstimatedMDMCheckInCycles'
    type: 'int'
  }
  {
    name: 'MDMCheckInCycleMethod'
    type: 'string'
  }
  {
    name: 'MDMEventWindowStartUtc'
    type: 'datetime'
  }
  {
    name: 'MDMEventsTruncated'
    type: 'boolean'
  }
  {
    name: 'MDMCycleEventsTruncated'
    type: 'boolean'
  }
  {
    name: 'MDMCycleOldestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'MDMScheduledTasks'
    type: 'dynamic'
  }
  {
    name: 'MDMScheduledTasksTruncated'
    type: 'boolean'
  }
  {
    name: 'MDMEvents'
    type: 'dynamic'
  }
  {
    name: 'CorrelationId'
    type: 'string'
  }
  {
    name: 'ExecutionId'
    type: 'string'
  }
  {
    name: 'ScriptVersion'
    type: 'string'
  }
  {
    name: 'RegistryWriteSuccess'
    type: 'boolean'
  }
  {
    name: 'BrokerUploadSuccess'
    type: 'boolean'
  }
  {
    name: 'Errors'
    type: 'dynamic'
  }
  {
    name: 'ErrorsTruncatedCount'
    type: 'int'
  }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    retentionInDays: retentionInDays
    sku: {
      name: 'PerGB2018'
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      disableLocalAuth: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    workspaceCapping: {
      dailyQuotaGb: dailyCapGb
    }
  }
}

resource telemetryTable 'Microsoft.OperationalInsights/workspaces/tables@2025-07-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    totalRetentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: concat([
        {
          name: 'TimeGenerated'
          type: 'datetime'
        }
      ], telemetryColumns)
    }
  }
}

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2021-04-01' = {
  name: dceName
  location: location
  tags: tags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  tags: tags
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      '${streamName}': {
        columns: telemetryColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'workspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'workspace'
        ]
        transformKql: 'source | extend TimeGenerated = BrokerReceivedTimestampUtc'
        outputStream: 'Custom-${tableName}'
      }
    ]
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    IngestionMode: 'LogAnalytics'
    DisableLocalAuth: true
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceName string = workspace.name
output tableName string = tableName
output dcrName string = dataCollectionRule.name
output dcrResourceId string = dataCollectionRule.id
output dcrImmutableId string = dataCollectionRule.properties.immutableId
output logsIngestionEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
output applicationInsightsConnectionString string = applicationInsights.properties.ConnectionString
