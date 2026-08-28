#requires -Version 5.1

$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$basePath = Join-Path $repositoryRoot 'scripts\intune\Intune-DeploymentTelemetry.ps1'
$pocPath = Join-Path $repositoryRoot 'scripts\intune\poc\Intune-DeploymentTelemetry-POC.ps1'
$generatorPath = Join-Path $repositoryRoot 'scripts\intune\poc\New-ConfiguredPocPlatformScript.ps1'

$expected = (Get-Content -LiteralPath $basePath -Raw).
    Replace(
        "`$UploadMode = 'Broker'",
        "`$UploadMode = 'DirectLogs'"
    ).
    Replace(
        "`$DirectTenantId = '<ENTRA-TENANT-ID>'",
        "`$DirectTenantId = '46b06a5e-8f7a-467b-bc9a-e776011fbb57'"
    ).
    Replace(
        "`$DirectClientId = '<APP-REGISTRATION-CLIENT-ID>'",
        "`$DirectClientId = '4020afa2-1ab1-4c8c-a615-3e20227b5545'"
    ).
    Replace(
        "`$DirectLogsIngestionEndpoint = 'https://<DCR-LOGS-INGESTION-ENDPOINT>'",
        "`$DirectLogsIngestionEndpoint = 'https://dcr-intunetlm-yhup4bd43eo3u-jk7e-italynorth.logs.z1.ingest.monitor.azure.com'"
    ).
    Replace(
        "`$DirectDcrImmutableId = '<DCR-IMMUTABLE-ID>'",
        "`$DirectDcrImmutableId = 'dcr-2374acb0c31441059e216089d568bb02'"
    )
$actual = Get-Content -LiteralPath $pocPath -Raw
if ($actual -ne $expected) {
    throw 'The versioned POC script is not synchronized with the base endpoint script.'
}

$pocTokens = $null
$pocErrors = $null
$pocAst = [Management.Automation.Language.Parser]::ParseInput(
    $actual,
    [ref]$pocTokens,
    [ref]$pocErrors
)
$secretAssignments = @(
    $pocAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'DirectClientSecret'
        },
        $true
    )
)
if ($secretAssignments.Count -ne 1 -or
    $secretAssignments[0].Right.Extent.Text -ne
        "'<APP-REGISTRATION-CLIENT-SECRET>'") {
    throw 'The versioned POC template contains a real or malformed client secret.'
}

$testDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    'intune-telemetry-poc-test-{0}' -f [guid]::NewGuid()
)
New-Item -ItemType Directory -Path $testDirectory | Out-Null
try {
    $secretPath = Join-Path $testDirectory 'test.secret.txt'
    Set-Content -LiteralPath $secretPath -Value 'test-secret-value' -NoNewline
    Push-Location $testDirectory
    try {
        $generatorOutput = & $generatorPath `
            -AssignmentTimestampUtc '2026-08-28T08:00:00Z' `
            -TemplatePath $pocPath `
            -SecretPath $secretPath `
            -OutputPath 'test.generated.ps1'
    }
    finally {
        Pop-Location
    }

    $outputPath = Join-Path $testDirectory 'test.generated.ps1'
    $generated = Get-Content -LiteralPath $outputPath -Raw
    if ($generated.Contains(
            "`$DirectClientSecret = '<APP-REGISTRATION-CLIENT-SECRET>'"
        ) -or
        -not $generated.Contains(
            "`$DirectClientSecret -eq '<APP-REGISTRATION-CLIENT-SECRET>'"
        ) -or
        $generated.Contains('<ASSIGNMENT-TIMESTAMP-UTC>') -or
        -not $generated.Contains(
            "`$DirectClientSecret = 'test-secret-value'"
        ) -or
        -not $generated.Contains(
            "`$AssignmentTimestampUtc = '2026-08-28T08:00:00.0000000+00:00'"
        )) {
        throw 'The POC script generator produced invalid configuration.'
    }
    if ($generatorOutput -notmatch
        'AssignmentTimestampUtc=2026-08-28T08:00:00\.0000000\+00:00') {
        throw 'The POC script generator did not report the stamped timestamp.'
    }
}
finally {
    if (Test-Path -LiteralPath $testDirectory) {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force
    }
}

Write-Output 'Versioned POC template and generator test passed.'
