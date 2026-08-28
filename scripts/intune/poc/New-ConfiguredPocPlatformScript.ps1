#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [datetimeoffset]$AssignmentTimestampUtc = [datetimeoffset]::UtcNow,

    [Parameter()]
    [string]$TemplatePath = (
        Join-Path $PSScriptRoot 'Intune-DeploymentTelemetry-POC.ps1'
    ),

    [Parameter()]
    [string]$SecretPath = (
        Join-Path $PSScriptRoot 'Intune-DeploymentTelemetry-POC.secret.txt'
    ),

    [Parameter()]
    [string]$OutputPath = (
        Join-Path $PSScriptRoot 'Intune-DeploymentTelemetry-POC.generated.ps1'
    )
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1.4'

$template = Get-Content -LiteralPath $TemplatePath -Raw
$secret = (Get-Content -LiteralPath $SecretPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($secret)) {
    throw 'The POC client secret file is empty.'
}
if ($secret.Contains("`r") -or $secret.Contains("`n")) {
    throw 'The POC client secret file must contain one line only.'
}

$secretPlaceholder = '<APP-REGISTRATION-CLIENT-SECRET>'
$secretAssignment = "`$DirectClientSecret = '$secretPlaceholder'"
$assignmentPlaceholder = '<ASSIGNMENT-TIMESTAMP-UTC>'
if ([regex]::Matches(
        $template,
        [regex]::Escape($secretAssignment)
    ).Count -ne 1) {
    throw 'The POC template must contain exactly one client-secret assignment placeholder.'
}
if ([regex]::Matches(
        $template,
        [regex]::Escape($assignmentPlaceholder)
    ).Count -ne 1) {
    throw 'The POC template must contain exactly one assignment timestamp placeholder.'
}

$effectiveAssignmentTimestamp = $AssignmentTimestampUtc.ToUniversalTime()
$configured = $template.Replace(
    $secretAssignment,
    "`$DirectClientSecret = '$($secret.Replace("'", "''"))'"
).Replace(
    $assignmentPlaceholder,
    $effectiveAssignmentTimestamp.ToString('o')
)

$parseTokens = $null
$parseErrors = $null
$configuredAst = [Management.Automation.Language.Parser]::ParseInput(
    $configured,
    [ref]$parseTokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw ($parseErrors | Out-String)
}

$requiredConfiguredVariables = @(
    'AssignmentTimestampUtc',
    'DirectTenantId',
    'DirectClientId',
    'DirectClientSecret',
    'DirectLogsIngestionEndpoint',
    'DirectDcrImmutableId'
)
$assignments = $configuredAst.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst]
    },
    $true
)
foreach ($variableName in $requiredConfiguredVariables) {
    $variableAssignments = @(
        $assignments |
            Where-Object {
                $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $_.Left.VariablePath.UserPath -eq $variableName
            }
    )
    if ($variableAssignments.Count -ne 1 -or
        $variableAssignments[0].Right.Extent.Text -match '<[^>]+>') {
        throw "Generated POC script has invalid configuration for `$$variableName."
    }
}

$fullOutputPath = $ExecutionContext.SessionState.Path.
    GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDirectory = Split-Path -Parent $fullOutputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
[IO.File]::WriteAllText(
    $fullOutputPath,
    $configured,
    [Text.UTF8Encoding]::new($true)
)

$secret = $null
$configured = $null
Write-Output (
    'Generated POC Platform Script {0}; AssignmentTimestampUtc={1}; Path={2}' -f
    $ScriptVersion,
    $effectiveAssignmentTimestamp.ToString('o'),
    $fullOutputPath
)
