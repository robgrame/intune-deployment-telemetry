# Deployment evidence workbook

Every deployment profile creates a shared Azure Monitor Workbook named
**Intune Deployment Evidence** and associates it with the solution's Log
Analytics workspace.

Open the workspace in the Azure portal, select **Workbooks**, and open
**Intune Deployment Evidence**. The default analysis window is 30 days and can
be changed from the workbook's **Analysis window** selector.

## Evidence included

- deployment population and P50, P95, and P99 latency;
- percentage of reached devices executing within 60 minutes;
- cumulative devices reached over time;
- device distribution across latency bands;
- daily percentile trend;
- likely delay classification from boot, MDM, and workload-specific IME
  evidence;
- PowerShell policy polling and empty-response counts since assignment;
- per-device records that can be exported to Excel;
- endpoint collection errors.

The Workbook keeps the first execution observed for each
`AzureAdDeviceId` in the selected period. Compare its reached-device count
with the intended Intune assignment population because devices that never
execute the script cannot report telemetry.

## Interpretation

`AssignmentToExecutionMinutes` is based on the assignment timestamp configured
in the script. In the manual POC workflow, that timestamp is stamped when the
configured script is generated, so the metric includes signing, upload, and
assignment delay. Broker-based environments can use the authoritative
assignment timestamp supplied by the deployment process.

The daily trend chart requires multiple distinct assignment timestamps. A
single-assignment POC produces one valid data point rather than a trend line.

The likely-cause chart uses the endpoint classification:

- `ProbablyOfflineBeforeBoot` means the last boot occurred after assignment;
- `ProbablyOfflineOrDisconnected` means neither MDM nor IME activity was found
  in a completely covered interval;
- `OnlineWithoutPowerShellPolling` means other management activity was present
  but the PowerShell workload did not request policies;
- `PowerShellPollingPolicyNotReturned` means polling occurred but Intune did
  not return the target policy;
- `PolicyLifecycleObservedWithoutReceiptMarker` means processing or execution
  was found even though the response marker was unavailable;
- `PolicyDeliveredThenExecutedPromptly` separates service/polling delay from
  execution delay;
- `InsufficientEvidence` is used whenever retained logs do not cover the
  complete interval or a log could not be parsed.

`EstimatedMDMCheckInCycles` is derived from bounded local Windows events and
is not an Intune service-side counter. IME parsing includes the active
`IntuneManagementExtension.log` and `AgentExecutor.log` files and all retained
rotated copies. Only bounded timestamps and counters are uploaded; policy
payloads, script content, stdout, and stderr are not retained. Coverage is
tracked separately for the management and AgentExecutor log families so a
longer retention period in one family cannot hide missing evidence in the
other.

## Infrastructure source

The Workbook definition is versioned at:

`infra\workbooks\deployment-evidence.workbook.json`

`infra\modules\observability.bicep` deploys it as a deterministic
`Microsoft.Insights/workbooks` resource and associates it with the Log
Analytics workspace. The `workbookName` and `workbookResourceId` deployment
outputs identify the created resource.
