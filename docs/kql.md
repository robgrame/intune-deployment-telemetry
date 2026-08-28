# 📊 KQL query library

The custom table is `IntuneDeploymentTelemetry_CL`.

Several of these queries are incorporated into the
[deployment evidence Workbook](deployment-workbook.md), which is deployed for
every solution profile. The additional queries below support ad-hoc analysis
and operational investigation.

## First devices reached

```kusto
IntuneDeploymentTelemetry_CL
| summarize FirstExecution=min(FirstExecutionTimestampUtc) by
    AzureAdDeviceId,
    DeviceName
| order by FirstExecution asc
```

## Highest assignment-to-execution delay

```kusto
IntuneDeploymentTelemetry_CL
| where isnotnull(AssignmentToExecutionMinutes)
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| project
    DeviceName,
    AzureAdDeviceId,
    AssignmentToExecutionMinutes,
    LastBootTimeUtc,
    UptimeHours,
    LastKnownMDMSync,
    EstimatedMDMCheckInCycles,
    MDMCheckInCycleMethod,
    IMEPolicyPollCountSinceAssignment,
    IMEEmptyPolicyResponseCount,
    IMEPolicyReceivedUtc,
    IMEExecutionIdentifiedUtc,
    IMEPolicyToExecutionSeconds,
    DeploymentDelayClassification,
    DeploymentDelayConfidence
| order by AssignmentToExecutionMinutes desc
```

## P50, P95, and P99 deployment latency

```kusto
IntuneDeploymentTelemetry_CL
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| where isnotnull(AssignmentToExecutionMinutes)
| summarize
    Devices=dcount(AzureAdDeviceId),
    P50Minutes=percentile(AssignmentToExecutionMinutes, 50),
    P95Minutes=percentile(AssignmentToExecutionMinutes, 95),
    P99Minutes=percentile(AssignmentToExecutionMinutes, 99)
```

## Device availability and delivery classification

```kusto
IntuneDeploymentTelemetry_CL
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| where isnotnull(AssignmentToExecutionMinutes)
| summarize Devices=count() by
    DeploymentDelayClassification,
    DeploymentDelayConfidence
| order by Devices desc
```

## IME PowerShell policy polling

```kusto
IntuneDeploymentTelemetry_CL
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| project
    DeviceName,
    AssignmentTimestampUtc,
    IMEPolicyPollCountSinceAssignment,
    IMEEmptyPolicyResponseCount,
    IMEDeviceCheckInCountSinceAssignment,
    IMEGenericWorkloadCheckInCount,
    IMEPolicyReceivedUtc,
    IMEExecutionIdentifiedUtc,
    IMEPolicyToExecutionSeconds,
    IMEManagementLogCoverageStatus,
    IMEAgentLogCoverageStatus,
    IMELogCoverageStatus,
    IMELogEvidenceTruncated
| order by IMEPolicyPollCountSinceAssignment desc
```

## MDM cycle distribution

```kusto
IntuneDeploymentTelemetry_CL
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| summarize
    Devices=count(),
    P50Cycles=percentile(EstimatedMDMCheckInCycles, 50),
    P95Cycles=percentile(EstimatedMDMCheckInCycles, 95),
    MaximumCycles=max(EstimatedMDMCheckInCycles)
    by MDMCheckInCycleMethod
```

`EstimatedMDMCheckInCycles` is evidence-based but remains an estimate derived
from bounded local DMEDP events. Use `MDMCheckInCycleMethod`,
`MDMCycleEventsTruncated`, and `MDMCycleOldestRetainedUtc` when assessing its
confidence.

## Broker-to-ingestion freshness

```kusto
IntuneDeploymentTelemetry_CL
| extend IngestionDelaySeconds =
    datetime_diff("second", ingestion_time(), BrokerReceivedTimestampUtc)
| summarize
    P50Seconds=percentile(IngestionDelaySeconds, 50),
    P95Seconds=percentile(IngestionDelaySeconds, 95),
    P99Seconds=percentile(IngestionDelaySeconds, 99)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

## Endpoint collection errors

```kusto
IntuneDeploymentTelemetry_CL
| where array_length(Errors) > 0
| mv-expand Error=Errors
| summarize
    Devices=dcount(AzureAdDeviceId),
    Occurrences=count()
    by Operation=tostring(Error.Operation), Message=tostring(Error.Message)
| order by Occurrences desc
```

## Certificate usage

```kusto
IntuneDeploymentTelemetry_CL
| summarize
    Devices=dcount(AzureAdDeviceId),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
    by ClientCertificateIssuerThumbprint
| order by LastSeen desc
```
