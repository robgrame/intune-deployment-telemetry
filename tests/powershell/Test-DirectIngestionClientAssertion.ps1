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

function ConvertFrom-TestBase64Url {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    return [Convert]::FromBase64String($base64)
}

$rsa = [Security.Cryptography.RSA]::Create(2048)
$certificate = $null
$publicKey = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=IntuneTelemetryPocTest',
        $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddMinutes(10)
    )
    $clientId = [guid]::NewGuid()
    $tokenEndpoint = [uri](
        'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f
        [guid]::NewGuid()
    )

    $assertion = New-DirectIngestionClientAssertion `
        -Certificate $certificate `
        -ClientId $clientId `
        -TokenEndpoint $tokenEndpoint
    $segments = $assertion.Split('.')
    if ($segments.Count -ne 3) {
        throw 'The client assertion must contain three JWT segments.'
    }

    $publicKey =
        [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $certificate
        )
    $signatureValid = $publicKey.VerifyData(
        [Text.Encoding]::ASCII.GetBytes("$($segments[0]).$($segments[1])"),
        (ConvertFrom-TestBase64Url -Value $segments[2]),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    if (-not $signatureValid) {
        throw 'The client assertion signature is invalid.'
    }

    $header = [Text.Encoding]::UTF8.GetString(
        (ConvertFrom-TestBase64Url -Value $segments[0])
    ) | ConvertFrom-Json
    $claims = [Text.Encoding]::UTF8.GetString(
        (ConvertFrom-TestBase64Url -Value $segments[1])
    ) | ConvertFrom-Json

    if ($header.alg -ne 'RS256' -or
        [string]::IsNullOrWhiteSpace([string]$header.'x5t#S256') -or
        $claims.iss -ne $clientId.ToString() -or
        $claims.sub -ne $clientId.ToString() -or
        $claims.aud -ne $tokenEndpoint.AbsoluteUri -or
        [long]$claims.exp -le [long]$claims.nbf) {
        throw 'The client assertion header or claims are invalid.'
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
        -Certificate $certificate `
        -IncludeSensitiveData $false
    if ($directPayload.Contains('UserUPN') -or
        $directPayload.Contains('CurrentLoggedOnUser') -or
        $directPayload.MDMEvents[0].PSObject.Properties['Message'] -or
        [string]::IsNullOrWhiteSpace(
            [string]$directPayload.BrokerReceivedTimestampUtc
        ) -or
        $directPayload.BrokerRequestId -ne $directPayload.ExecutionId -or
        [string]::IsNullOrWhiteSpace(
            [string]$directPayload.ClientCertificateThumbprint
        )) {
        throw 'Direct payload minimization or metadata enrichment failed.'
    }
}
finally {
    if ($null -ne $publicKey) {
        $publicKey.Dispose()
    }
    if ($null -ne $certificate) {
        $certificate.Dispose()
    }
    $rsa.Dispose()
}

Write-Output 'Direct-ingestion client assertion test passed.'
