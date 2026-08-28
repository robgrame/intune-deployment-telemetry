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

@description('Deploy Application Insights for broker observability.')
param deployApplicationInsights bool = true

@description('Deploy a separate Data Collection Endpoint.')
param deployDataCollectionEndpoint bool = true

@description('Optional service principal object ID granted direct ingestion access.')
param ingestionPrincipalId string = ''

param tags object

var workspaceName = 'law-${resourcePrefix}-${uniqueSuffix}'
var applicationInsightsName = 'appi-${resourcePrefix}-${uniqueSuffix}'
var dceName = 'dce-${resourcePrefix}-${uniqueSuffix}'
var dcrName = 'dcr-${resourcePrefix}-${uniqueSuffix}'
var workbookDisplayName = 'Intune Deployment Evidence'
var workbookName = guid(workspace.id, 'intune-deployment-evidence')
var tableName = 'IntuneDeploymentTelemetry_CL'
var streamName = 'Custom-IntuneDeploymentTelemetry'
var workbookSerializedData = replace(
  loadTextContent('../workbooks/deployment-evidence.workbook.json'),
  '__WORKSPACE_RESOURCE_ID__',
  workspace.id
)
var workbookTags = union(tags, {
  'hidden-title': workbookDisplayName
})
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
    name: 'ConfiguredIntunePolicyId'
    type: 'string'
  }
  {
    name: 'DetectedIntunePolicyId'
    type: 'string'
  }
  {
    name: 'IntunePolicyIdMatchStatus'
    type: 'string'
  }
  {
    name: 'IMEPolicyPollCountSinceAssignment'
    type: 'int'
  }
  {
    name: 'IMEEmptyPolicyResponseCount'
    type: 'int'
  }
  {
    name: 'IMEDeviceCheckInCountSinceAssignment'
    type: 'int'
  }
  {
    name: 'IMEGenericWorkloadCheckInCount'
    type: 'int'
  }
  {
    name: 'IMEPolicyPollTimestampsUtc'
    type: 'dynamic'
  }
  {
    name: 'IMEPolicyPollTimestampsTruncated'
    type: 'boolean'
  }
  {
    name: 'IMEPolicyReceivedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEPolicyProcessingUtc'
    type: 'datetime'
  }
  {
    name: 'IMEScriptMaterializedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEExecutionIdentifiedUtc'
    type: 'datetime'
  }
  {
    name: 'AssignmentToIMEExecutionMinutes'
    type: 'real'
  }
  {
    name: 'IMEPolicyToExecutionSeconds'
    type: 'real'
  }
  {
    name: 'IMELogOldestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMELogNewestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEManagementLogOldestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEManagementLogNewestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEAgentLogOldestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEAgentLogNewestRetainedUtc'
    type: 'datetime'
  }
  {
    name: 'IMEManagementLogCoverageStatus'
    type: 'string'
  }
  {
    name: 'IMEAgentLogCoverageStatus'
    type: 'string'
  }
  {
    name: 'IMELogFilesAnalyzed'
    type: 'int'
  }
  {
    name: 'IMELogFilesFailed'
    type: 'int'
  }
  {
    name: 'IMELogCoverageStatus'
    type: 'string'
  }
  {
    name: 'IMELogEvidenceTruncated'
    type: 'boolean'
  }
  {
    name: 'DeploymentDelayClassification'
    type: 'string'
  }
  {
    name: 'DeploymentDelayConfidence'
    type: 'string'
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

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2021-04-01' = if (deployDataCollectionEndpoint) {
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
  dependsOn: [
    telemetryTable
  ]
  properties: {
    dataCollectionEndpointId: deployDataCollectionEndpoint ? dataCollectionEndpoint.id : null
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

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = if (deployApplicationInsights) {
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

resource deploymentEvidenceWorkbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookName
  location: location
  kind: 'shared'
  tags: workbookTags
  properties: {
    displayName: workbookDisplayName
    serializedData: workbookSerializedData
    version: '1.0'
    sourceId: workspace.id
    category: 'workbook'
  }
}

var monitoringMetricsPublisherRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '3913510d-42f4-4e42-8a64-420c390055eb'
)

resource directIngestionPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(ingestionPrincipalId)) {
  name: guid(dataCollectionRule.id, ingestionPrincipalId, monitoringMetricsPublisherRoleId)
  scope: dataCollectionRule
  properties: {
    principalId: ingestionPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: monitoringMetricsPublisherRoleId
  }
}

output workspaceName string = workspace.name
output tableName string = tableName
output dcrName string = dataCollectionRule.name
output dcrResourceId string = dataCollectionRule.id
output dcrImmutableId string = dataCollectionRule.properties.immutableId
output workbookName string = deploymentEvidenceWorkbook.name
output workbookResourceId string = deploymentEvidenceWorkbook.id
output logsIngestionEndpoint string = deployDataCollectionEndpoint
  ? dataCollectionEndpoint!.properties.logsIngestion.endpoint
  : dataCollectionRule.properties.endpoints.logsIngestion
output applicationInsightsConnectionString string = deployApplicationInsights
  ? applicationInsights!.properties.ConnectionString
  : ''
