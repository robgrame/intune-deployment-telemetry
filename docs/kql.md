# 📊 KQL query library

The custom table is `IntuneDeploymentTelemetry_CL`.

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
    MDMCheckInCycleMethod
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

## Device availability classification

```kusto
IntuneDeploymentTelemetry_CL
| summarize arg_min(FirstExecutionTimestampUtc, *) by AzureAdDeviceId
| extend
    BootAfterAssignment = LastBootTimeUtc > AssignmentTimestampUtc,
    MdmSyncAfterAssignment = LastKnownMDMSync >= AssignmentTimestampUtc
| extend LikelyCause = case(
    BootAfterAssignment and UptimeHours < 2,
        "Device was likely offline",
    MdmSyncAfterAssignment and EstimatedMDMCheckInCycles > 1,
        "Multiple MDM cycles before execution",
    not(MdmSyncAfterAssignment),
        "No local MDM activity after assignment",
    "Requires event-level review")
| summarize Devices=count() by LikelyCause
| order by Devices desc
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
