#requires -Version 7.0

$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot '..\..\scripts\intune\Intune-DeploymentTelemetry.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw ($parseErrors | Out-String)
}

$expectedValues = @{
    IntunePolicyId               = '<INTUNE-POLICY-ID>'
    DirectTenantId              = '<ENTRA-TENANT-ID>'
    DirectClientId              = '<APP-REGISTRATION-CLIENT-ID>'
    DirectClientSecret          = '<APP-REGISTRATION-CLIENT-SECRET>'
    DirectLogsIngestionEndpoint = 'https://<DCR-LOGS-INGESTION-ENDPOINT>'
    DirectDcrImmutableId        = '<DCR-IMMUTABLE-ID>'
}

$assignments = $ast.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst]
    },
    $true
)

foreach ($entry in $expectedValues.GetEnumerator()) {
    $matches = @(
        $assignments |
            Where-Object {
                $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $_.Left.VariablePath.UserPath -eq $entry.Key
            }
    )
    if ($matches.Count -ne 1) {
        throw "Expected exactly one assignment for `$$($entry.Key); found $($matches.Count)."
    }

    $rightAst = $matches[0].Right
    $valueAst = if (
        $rightAst -is [Management.Automation.Language.CommandExpressionAst]
    ) {
        $rightAst.Expression
    } else {
        $rightAst
    }
    if ($valueAst -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
        $valueAst.Value -ne $entry.Value) {
        throw "Tracked endpoint script contains a configured value for `$$($entry.Key)."
    }
}

Write-Output 'Tracked endpoint script contains only the required POC placeholders.'
