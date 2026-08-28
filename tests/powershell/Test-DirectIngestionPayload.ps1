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

$functions = $ast.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    },
    $true
)
foreach ($function in $functions) {
    . ([scriptblock]::Create($function.Extent.Text))
}

$tokenFunction = $functions |
    Where-Object Name -eq 'Get-DirectIngestionAccessToken' |
    Select-Object -First 1
if ($null -eq $tokenFunction) {
    throw 'Get-DirectIngestionAccessToken was not found.'
}
$tokenFunctionText = $tokenFunction.Extent.Text
foreach ($requiredFragment in @(
    "client_id     = `$ClientId.ToString()",
    'client_secret = $ClientSecret',
    "scope         = 'https://monitor.azure.com//.default'",
    "grant_type    = 'client_credentials'",
    "'https://login.microsoftonline.com/{0}/oauth2/v2.0/token'"
)) {
    if (-not $tokenFunctionText.Contains($requiredFragment)) {
        throw "Direct token request is missing: $requiredFragment"
    }
}

$payload = [ordered]@{
    ExecutionId         = [guid]::NewGuid().ToString()
    UserUPN             = 'user@example.com'
    CurrentLoggedOnUser = 'CONTOSO\User'
    MDMEvents           = @(
        [pscustomobject]@{
            EventId = 814
            Message = 'Sensitive event text'
        }
    )
}
$directPayload = ConvertTo-DirectIngestionPayload `
    -Payload $payload `
    -IncludeSensitiveData $false

if ($directPayload.Contains('UserUPN') -or
    $directPayload.Contains('CurrentLoggedOnUser') -or
    $directPayload.MDMEvents[0].PSObject.Properties['Message'] -or
    [string]::IsNullOrWhiteSpace(
        [string]$directPayload.BrokerReceivedTimestampUtc
    ) -or
    $directPayload.BrokerRequestId -ne $directPayload.ExecutionId -or
    -not $directPayload.Contains('ClientCertificateThumbprint') -or
    -not $directPayload.Contains('ClientCertificateIssuerThumbprint') -or
    $null -ne $directPayload.ClientCertificateThumbprint -or
    $null -ne $directPayload.ClientCertificateIssuerThumbprint) {
    throw 'Direct payload minimization or metadata enrichment failed.'
}

Write-Output 'Direct-ingestion payload test passed.'
