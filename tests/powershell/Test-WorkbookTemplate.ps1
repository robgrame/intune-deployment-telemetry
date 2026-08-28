#requires -Version 7.0

$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$workbookPath = Join-Path $repositoryRoot (
    'infra\workbooks\deployment-evidence.workbook.json'
)
$workbook = Get-Content -LiteralPath $workbookPath -Raw |
    ConvertFrom-Json -Depth 100

if ($workbook.version -ne 'Notebook/1.0') {
    throw 'The deployment-evidence workbook has an unsupported version.'
}
if (@($workbook.fallbackResourceIds).Count -ne 1 -or
    $workbook.fallbackResourceIds[0] -ne '__WORKSPACE_RESOURCE_ID__') {
    throw 'The workbook must contain exactly one workspace placeholder.'
}

$parameters = @(
    $workbook.items |
        Where-Object { $_.type -eq 9 }
)
if ($parameters.Count -ne 1 -or
    @($parameters[0].content.parameters |
        Where-Object { $_.name -eq 'TimeRange' }).Count -ne 1) {
    throw 'The workbook must contain exactly one TimeRange parameter.'
}

$queries = @(
    $workbook.items |
        Where-Object { $_.type -eq 3 }
)
if ($queries.Count -lt 6) {
    throw 'The workbook must contain at least six evidence queries.'
}
foreach ($query in $queries) {
    if ($query.content.query -notmatch '\bIntuneDeploymentTelemetry_CL\b') {
        throw "Workbook query '$($query.name)' does not use the telemetry table."
    }
    if ($query.content.timeContextFromParameter -ne 'TimeRange') {
        throw "Workbook query '$($query.name)' does not use TimeRange."
    }
}

$requiredVisualizations = @(
    'tiles',
    'timechart',
    'barchart',
    'piechart',
    'table'
)
foreach ($visualization in $requiredVisualizations) {
    if ($visualization -notin @($queries.content.visualization)) {
        throw "Workbook visualization '$visualization' is missing."
    }
}

Write-Output 'Deployment-evidence workbook template test passed.'
