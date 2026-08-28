#requires -Version 5.1

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

function New-CmTraceLine {
    param(
        [Parameter(Mandatory)]
        [datetime]$Timestamp,

        [Parameter(Mandatory)]
        [string]$Message
    )

    return '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="Test" context="" type="1" thread="1" file="">' -f
        $Message,
        $Timestamp.ToString('HH:mm:ss.fffffff'),
        $Timestamp.ToString('M-d-yyyy')
}

$policyId = '5d645e5c-d175-4374-81d3-edd1e211a100'
$accountId = '9c1083cc-2c75-45b7-85a8-c6c87cf2d691'
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) (
    'intune-telemetry-ime-test-{0}' -f [guid]::NewGuid()
)
New-Item -ItemType Directory -Path $testDirectory | Out-Null

try {
    $assignmentLocal = [datetime]::SpecifyKind(
        [datetime]'2026-08-28T11:00:00',
        [DateTimeKind]::Unspecified
    )
    $collectionEndLocal = [datetime]::SpecifyKind(
        [datetime]'2026-08-28T14:46:00',
        [DateTimeKind]::Unspecified
    )
    $assignmentUtc = [TimeZoneInfo]::ConvertTimeToUtc(
        $assignmentLocal,
        [TimeZoneInfo]::Local
    )
    $collectionEndUtc = [TimeZoneInfo]::ConvertTimeToUtc(
        $collectionEndLocal,
        [TimeZoneInfo]::Local
    )

    $firstRequest = New-CmTraceLine -Timestamp ([datetime]'2026-08-28T11:10:00') `
        -Message '[PowerShell] Requesting policies with session id 11111111-1111-1111-1111-111111111111 ...'
    $emptyResponse = New-CmTraceLine -Timestamp ([datetime]'2026-08-28T11:10:01') `
        -Message '[PowerShell] response payload is []'
    $rotatedLines = @(
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T10:59:00') `
            -Message 'Log coverage before assignment'
        $firstRequest
        $emptyResponse
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T12:00:00') `
            -Message '[ServiceBase], check in using device check in AAD App'
    )
    $activeLines = @(
        $firstRequest
        $emptyResponse
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T13:00:00') `
            -Message '[GenericWorkload] Initiating GenericWorkload Checkin'
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:45:00') `
            -Message '[PowerShell] Requesting policies with session id 22222222-2222-2222-2222-222222222222 ...'
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:45:02') `
            -Message "[PowerShell] response payload is [{`"PolicyId`":`"$policyId`"}]"
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:45:03') `
            -Message "[PowerShell] Processing policy $policyId"
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:45:05') `
            -Message "[PowerShell] Decryption completed successfully for $policyId"
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:46:00') `
            -Message 'Log coverage after execution'
    )
    $agentLines = @(
        ''
        'Unstructured preamble without a CMTrace timestamp'
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:45:06') `
            -Message ("Adding argument powershell with value`n" +
                "C:\Windows\IMECache\${accountId}_${policyId}.ps1")
    )

    Set-Content -LiteralPath (
        Join-Path $testDirectory 'IntuneManagementExtension-20260828.log'
    ) -Value $rotatedLines -Encoding UTF8
    Set-Content -LiteralPath (
        Join-Path $testDirectory 'IntuneManagementExtension.log'
    ) -Value $activeLines -Encoding UTF8
    Set-Content -LiteralPath (
        Join-Path $testDirectory 'AgentExecutor.log'
    ) -Value $agentLines -Encoding UTF8

    $identity = Get-IntunePolicyIdentity -ConfiguredPolicyId $policyId `
        -ExecutingScriptPath "C:\Windows\IMECache\${accountId}_${policyId}.ps1"
    if ($identity.MatchStatus -ne 'ConfiguredAndDetectedMatch' -or
        $identity.EffectivePolicyId -ne $policyId) {
        throw 'Policy identity correlation failed.'
    }
    $mismatchedIdentity = Get-IntunePolicyIdentity `
        -ConfiguredPolicyId $accountId `
        -ExecutingScriptPath "C:\Windows\IMECache\${accountId}_${policyId}.ps1"
    if ($mismatchedIdentity.MatchStatus -ne
        'ConfiguredAndDetectedMismatch' -or
        $mismatchedIdentity.DetectedPolicyId -ne $policyId -or
        $mismatchedIdentity.EffectivePolicyId -ne $policyId) {
        throw 'Account ID was incorrectly accepted as the Policy ID.'
    }
    $numberedIdentity = Get-IntunePolicyIdentity `
        -ConfiguredPolicyId '<INTUNE-POLICY-ID>' `
        -ExecutingScriptPath "C:\Windows\IMECache\$policyId`_1\detect.ps1"
    if ($numberedIdentity.MatchStatus -ne 'DetectedFromScriptPath' -or
        $numberedIdentity.EffectivePolicyId -ne $policyId) {
        throw 'Numbered IME policy path detection failed.'
    }
    $singleGuidIdentity = Get-IntunePolicyIdentity `
        -ConfiguredPolicyId '<INTUNE-POLICY-ID>' `
        -ExecutingScriptPath "C:\Windows\IMECache\$accountId.ps1"
    if ($singleGuidIdentity.MatchStatus -ne 'Unavailable' -or
        $null -ne $singleGuidIdentity.EffectivePolicyId) {
        throw 'An unstructured single GUID path was treated as a Policy ID.'
    }

    $evidence = Get-ImeLogEvidence -AssignmentUtc $assignmentUtc `
        -CollectionEndUtc $collectionEndUtc `
        -PolicyId $policyId `
        -MaximumPollTimestamps 100 `
        -LogDirectoryPath $testDirectory

    if ($evidence.LogFilesAnalyzed -ne 3 -or
        $evidence.LogFilesFailed -ne 0 -or
        $evidence.LogCoverageStatus -ne 'Complete' -or
        $evidence.ManagementLogCoverageStatus -ne 'Complete' -or
        $evidence.AgentLogCoverageStatus -ne 'ExecutionMarkerFound' -or
        $evidence.LogEvidenceTruncated -or
        $evidence.PolicyPollCountSinceAssignment -ne 2 -or
        $evidence.EmptyPolicyResponseCount -ne 1 -or
        $evidence.DeviceCheckInCountSinceAssignment -ne 1 -or
        $evidence.GenericWorkloadCheckInCount -ne 1 -or
        $evidence.PolicyPollTimestampsUtc.Count -ne 2 -or
        -not $evidence.PolicyReceivedUtc -or
        -not $evidence.PolicyProcessingUtc -or
        -not $evidence.ScriptMaterializedUtc -or
        -not $evidence.ExecutionIdentifiedUtc) {
        throw (
            'IME active/rotated log parsing or deduplication failed: {0}' -f
            ($evidence | ConvertTo-Json -Depth 5 -Compress)
        )
    }

    $classification = Get-DeploymentDelayClassification `
        -ImeEvidence $evidence `
        -MdmCycleCount 1 `
        -AssignmentUtc $assignmentUtc `
        -LastBootUtc $assignmentUtc.AddDays(-1)
    if ($classification.Classification -ne
        'PolicyDeliveredThenExecutedPromptly' -or
        $classification.Confidence -ne 'High') {
        throw 'IME delay classification failed.'
    }
    $postPollBootClassification = Get-DeploymentDelayClassification `
        -ImeEvidence $evidence `
        -MdmCycleCount 0 `
        -AssignmentUtc $assignmentUtc `
        -LastBootUtc $assignmentUtc.AddHours(2)
    if ($postPollBootClassification.Classification -eq
        'ProbablyOfflineBeforeBoot') {
        throw 'Pre-boot IME activity was ignored by delay classification.'
    }
    $lifecycleOnlyEvidence = [pscustomobject]@{
        LogCoverageStatus                 = 'Complete'
        LogEvidenceTruncated              = $false
        PolicyPollCountSinceAssignment    = 0
        DeviceCheckInCountSinceAssignment = 0
        GenericWorkloadCheckInCount       = 0
        FirstManagementActivityUtc        = ConvertTo-UtcIso8601 `
            -Value $assignmentUtc.AddMinutes(30)
        PolicyReceivedUtc                 = $null
        PolicyProcessingUtc               = ConvertTo-UtcIso8601 `
            -Value $assignmentUtc.AddMinutes(30)
        ScriptMaterializedUtc             = ConvertTo-UtcIso8601 `
            -Value $assignmentUtc.AddMinutes(31)
        ExecutionIdentifiedUtc            = ConvertTo-UtcIso8601 `
            -Value $assignmentUtc.AddMinutes(32)
    }
    $lifecycleOnlyClassification = Get-DeploymentDelayClassification `
        -ImeEvidence $lifecycleOnlyEvidence `
        -MdmCycleCount 0 `
        -AssignmentUtc $assignmentUtc `
        -LastBootUtc $assignmentUtc.AddHours(2)
    if ($lifecycleOnlyClassification.Classification -ne
        'PolicyLifecycleObservedWithoutReceiptMarker') {
        throw 'Policy lifecycle evidence was incorrectly classified as offline.'
    }

    $partialDirectory = Join-Path $testDirectory 'partial'
    New-Item -ItemType Directory -Path $partialDirectory | Out-Null
    Set-Content -LiteralPath (
        Join-Path $partialDirectory 'IntuneManagementExtension.log'
    ) -Value @(
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T13:00:00') `
            -Message '[PowerShell] Requesting policies with session id 33333333-3333-3333-3333-333333333333 ...'
    ) -Encoding UTF8
    Set-Content -LiteralPath (
        Join-Path $partialDirectory 'AgentExecutor-20260828.log'
    ) -Value @(
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T10:00:00') `
            -Message 'Old AgentExecutor evidence'
        New-CmTraceLine -Timestamp ([datetime]'2026-08-28T14:46:00') `
            -Message 'Recent AgentExecutor evidence'
    ) -Encoding UTF8

    $partialEvidence = Get-ImeLogEvidence -AssignmentUtc $assignmentUtc `
        -CollectionEndUtc $collectionEndUtc `
        -PolicyId $policyId `
        -MaximumPollTimestamps 100 `
        -LogDirectoryPath $partialDirectory
    if ($partialEvidence.ManagementLogCoverageStatus -ne
        'AssignmentPredatesRetainedLogs' -or
        $partialEvidence.LogCoverageStatus -ne 'Partial') {
        throw 'Separate IME and AgentExecutor retention validation failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testDirectory) {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force
    }
}

Write-Output 'IME active and rotated log evidence test passed.'
