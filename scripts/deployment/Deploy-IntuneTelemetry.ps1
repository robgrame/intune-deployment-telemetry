#requires -Version 5.1

<#
.SYNOPSIS
Deploys an Intune Deployment Telemetry environment.

.DESCRIPTION
Selects the dedicated minimal template for a Proof of Concept deployment or
the broker template for dev, prod, and premium. Sensitive certificate material
is passed to Bicep through temporary process environment variables.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('poc', 'dev', 'prod', 'premium')]
    [string]$DeploymentType,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Subscription,

    [Parameter()]
    [ValidateScript({
        foreach ($path in $_) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Trusted root certificate file not found: $path"
            }
        }
        return $true
    })]
    [string[]]$TrustedRootCertificatePaths,

    [Parameter()]
    [string[]]$TrustedIssuerCaSha256Thumbprints,

    [Parameter()]
    [guid]$PocServicePrincipalObjectId,

    [Parameter()]
    [switch]$WhatIfOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '1.0.1'

function Invoke-AzureCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed with exit code ${LASTEXITCODE}: az $($Arguments -join ' ')"
    }
}

function ConvertTo-NormalizedSha256Fingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $normalized = ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{64}$') {
        throw 'Every issuing CA fingerprint must contain 64 hexadecimal characters.'
    }
    return $normalized
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$mainTemplate = Join-Path $repositoryRoot 'infra\main.bicep'
$pocTemplate = Join-Path $repositoryRoot 'infra\poc.bicep'
$parameterFile = Join-Path $repositoryRoot (
    'infra\environments\{0}.bicepparam' -f $DeploymentType
)

$previousTrustedRoots = $env:INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64
$previousIssuerFingerprints =
    $env:INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS
$previousPocPrincipal =
    $env:INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID

try {
    Write-Output (
        'Starting deployment script {0}. Type={1}; ResourceGroup={2}' -f
        $ScriptVersion,
        $DeploymentType,
        $ResourceGroupName
    )

    Invoke-AzureCli -Arguments @('account', 'show', '--output', 'none')
    if (-not [string]::IsNullOrWhiteSpace($Subscription)) {
        Invoke-AzureCli -Arguments @(
            'account',
            'set',
            '--subscription',
            $Subscription
        )
    }
    Invoke-AzureCli -Arguments @(
        'group',
        'show',
        '--name',
        $ResourceGroupName,
        '--output',
        'none'
    )

    if ($DeploymentType -eq 'poc') {
        if ($PocServicePrincipalObjectId -eq [guid]::Empty) {
            throw 'PocServicePrincipalObjectId is required for a POC deployment.'
        }

        $templateFile = $pocTemplate
        $env:INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID =
            $PocServicePrincipalObjectId.ToString()
        Remove-Item Env:INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64 `
            -ErrorAction SilentlyContinue
        Remove-Item Env:INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS `
            -ErrorAction SilentlyContinue
    }
    else {
        if ($null -eq $TrustedRootCertificatePaths -or
            $TrustedRootCertificatePaths.Count -eq 0) {
            throw 'TrustedRootCertificatePaths is required for dev, prod, and premium deployments.'
        }
        if ($null -eq $TrustedIssuerCaSha256Thumbprints -or
            $TrustedIssuerCaSha256Thumbprints.Count -eq 0) {
            throw 'TrustedIssuerCaSha256Thumbprints is required for dev, prod, and premium deployments.'
        }

        $encodedRoots = @(
            foreach ($rootPath in $TrustedRootCertificatePaths) {
                $certificatePath = (Resolve-Path -LiteralPath $rootPath).Path
                $certificateBytes = [IO.File]::ReadAllBytes($certificatePath)
                $certificate =
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                        $certificateBytes
                    )
                try {
                    $isCertificateAuthority = @(
                        $certificate.Extensions |
                            Where-Object {
                                $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and
                                $_.CertificateAuthority
                            }
                    ).Count -gt 0
                    if (-not $isCertificateAuthority) {
                        throw "Trusted root file must contain a CA certificate: $certificatePath"
                    }
                }
                finally {
                    $certificate.Dispose()
                }
                [Convert]::ToBase64String($certificateBytes)
            }
        )

        $normalizedIssuers = @(
            $TrustedIssuerCaSha256Thumbprints |
                ForEach-Object {
                    ConvertTo-NormalizedSha256Fingerprint -Value $_
                } |
                Select-Object -Unique
        )
        $templateFile = $mainTemplate
        $env:INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64 =
            $encodedRoots -join ';'
        $env:INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS =
            $normalizedIssuers -join ';'
        Remove-Item Env:INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID `
            -ErrorAction SilentlyContinue
    }

    Invoke-AzureCli -Arguments @(
        'bicep',
        'build',
        '--file',
        $templateFile,
        '--stdout'
    ) | Out-Null

    $deploymentArguments = @(
        '--resource-group',
        $ResourceGroupName,
        '--template-file',
        $templateFile,
        '--parameters',
        $parameterFile
    )
    Invoke-AzureCli -Arguments (
        @('deployment', 'group', 'what-if') + $deploymentArguments
    )

    if ($WhatIfOnly) {
        Write-Output 'What-if completed; deployment was not started.'
        return
    }

    $deploymentName = 'intune-telemetry-{0}-{1}' -f
        $DeploymentType,
        [datetime]::UtcNow.ToString('yyyyMMddHHmmss')
    Invoke-AzureCli -Arguments (
        @(
            'deployment',
            'group',
            'create',
            '--name',
            $deploymentName
        ) +
        $deploymentArguments +
        @(
            '--query',
            'properties.outputs',
            '--output',
            'jsonc'
        )
    )
}
finally {
    $env:INTUNE_TELEMETRY_TRUSTED_ROOTS_BASE64 = $previousTrustedRoots
    $env:INTUNE_TELEMETRY_ISSUER_CA_SHA256_THUMBPRINTS =
        $previousIssuerFingerprints
    $env:INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID =
        $previousPocPrincipal
}
