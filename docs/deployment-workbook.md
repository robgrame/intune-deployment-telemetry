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
- likely delay classification from boot and local MDM evidence;
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

The likely-cause chart is evidence-based rather than authoritative:

- a boot after assignment with low uptime suggests that the device was
  offline;
- multiple local MDM cycles suggest delivery required more than one check-in;
- no local MDM activity after assignment suggests the device did not check in;
- remaining devices require event-level investigation.

`EstimatedMDMCheckInCycles` is derived from bounded local Windows events and
is not an Intune service-side counter.

## Infrastructure source

The Workbook definition is versioned at:

`infra\workbooks\deployment-evidence.workbook.json`

`infra\modules\observability.bicep` deploys it as a deterministic
`Microsoft.Insights/workbooks` resource and associates it with the Log
Analytics workspace. The `workbookName` and `workbookResourceId` deployment
outputs identify the created resource.
