#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
Collects local Windows and MDM telemetry for Intune deployment-latency analysis.

.DESCRIPTION
Designed for Microsoft Intune Platform Scripts running as SYSTEM in a 64-bit
Windows PowerShell host. The first execution timestamp and correlation ID are
written once to HKLM and never overwritten.

Broker mode sends telemetry over mutual TLS without storing Azure credentials
on the endpoint. DirectLogs is a Proof of Concept mode that embeds a live
Microsoft Entra client secret in the configuration block and sends directly
to an Azure Monitor DCR. Treat every configured DirectLogs copy as a secret
artifact: never commit it and revoke the credential when the POC ends.
#>

#region Configuration - set these values before signing and uploading to Intune
$UploadMode = 'DirectLogs'
$BrokerUri = 'https://<FUNCTION-APP-HOSTNAME>/api/telemetry'
$AssignmentTimestampUtc = '<ASSIGNMENT-TIMESTAMP-UTC>'
$TrustedIssuerCaSha256Thumbprints = @(
    '<ISSUING-CA-SHA256-THUMBPRINT>'
)
$DirectTenantId = '46b06a5e-8f7a-467b-bc9a-e776011fbb57'
$DirectClientId = '4020afa2-1ab1-4c8c-a615-3e20227b5545'
$DirectClientSecret = '<APP-REGISTRATION-CLIENT-SECRET>'
$DirectLogsIngestionEndpoint = 'https://dcr-intunetlm-yhup4bd43eo3u-jk7e-italynorth.logs.z1.ingest.monitor.azure.com'
$DirectDcrImmutableId = 'dcr-2374acb0c31441059e216089d568bb02'
$DirectStreamName = 'Custom-IntuneDeploymentTelemetry'
$DirectIncludeSensitiveData = $false
$EventLookbackHours = 72
$MaximumMdmEvents = 20
$UploadRetryCount = 4
$UploadTimeoutSeconds = 30
$SkipUpload = $false
#endregion Configuration

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '1.4.6'
$RegistryPath = 'HKLM:\SOFTWARE\Bigfix Tags\IntuneDeploymentTelemetry'
$LogDirectory = Join-Path $env:ProgramData 'IntuneDeploymentTelemetry'
$TranscriptPath = $null
$MdmAdminLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
$script:Errors = [System.Collections.Generic.List[object]]::new()
$script:TranscriptStarted = $false
$script:LocalStorageReady = $false

function ConvertTo-UtcIso8601 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$Value
    )

    return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-OptionalUtcIso8601 {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    try {
        if ($Value -is [datetime]) {
            return ConvertTo-UtcIso8601 -Value $Value
        }

        $fileTime = 0L
        if ([long]::TryParse([string]$Value, [ref]$fileTime) -and
            $fileTime -gt 100000000000000000L) {
            return ConvertTo-UtcIso8601 -Value ([datetime]::FromFileTimeUtc($fileTime))
        }

        $parsed = [datetime]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeLocal
        )
        return ConvertTo-UtcIso8601 -Value $parsed
    }
    catch {
        return $null
    }
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Add-TelemetryError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Operation,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $entry = [ordered]@{
        TimestampUtc = ConvertTo-UtcIso8601 -Value ([datetime]::UtcNow)
        Operation    = $Operation
        Message      = $ErrorRecord.Exception.Message
        ErrorType    = $ErrorRecord.Exception.GetType().FullName
        HResult      = ('0x{0:X8}' -f ($ErrorRecord.Exception.HResult -band 0xffffffff))
    }

    $script:Errors.Add([pscustomobject]$entry)
    Write-Warning ('{0}: {1}' -f $Operation, $ErrorRecord.Exception.Message)
}

function Get-TelemetryErrorSnapshot {
    [CmdletBinding()]
    param()

    $maximumErrors = 25
    return [pscustomobject]@{
        Errors         = @($script:Errors | Select-Object -First $maximumErrors)
        TruncatedCount = [Math]::Max(0, $script:Errors.Count - $maximumErrors)
    }
}

function Invoke-TelemetryOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [Parameter()]
        $Default = $null
    )

    try {
        return & $Operation
    }
    catch {
        Add-TelemetryError -Operation $Name -ErrorRecord $_
        return $Default
    }
}

function Initialize-LocalLogging {
    [CmdletBinding()]
    param()

    try {
        $directoryExisted = Test-Path -LiteralPath $LogDirectory -PathType Container
        if (-not $directoryExisted) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }

        $directory = Get-Item -LiteralPath $LogDirectory -Force
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to use reparse-point log directory: $LogDirectory"
        }

        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $systemSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid, $null
        )
        $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
        )
        $allowedSids = @($systemSid.Value, $administratorsSid.Value)
        if ($directoryExisted) {
            $existingAcl = Get-Acl -LiteralPath $LogDirectory
            $unexpectedAllow = @($existingAcl.Access | Where-Object {
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]
                ).Value -notin $allowedSids
            })
            if (-not $existingAcl.AreAccessRulesProtected -or $unexpectedAllow.Count -gt 0) {
                throw 'Existing telemetry directory does not have the required protected ACL.'
            }
        }

        foreach ($sid in @($systemSid, $administratorsSid)) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                $allow
            )
            $acl.AddAccessRule($rule)
        }
        $acl.SetOwner($administratorsSid)
        Set-Acl -LiteralPath $LogDirectory -AclObject $acl -ErrorAction Stop

        $script:TranscriptPath = Join-Path $LogDirectory (
            'IntuneDeploymentTelemetry-{0}.log' -f [guid]::NewGuid().ToString('N')
        )
        Get-ChildItem -LiteralPath $LogDirectory -Filter 'IntuneDeploymentTelemetry-*.log' -File |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -Skip 9 |
            Remove-Item -Force
        Get-ChildItem -LiteralPath $LogDirectory -Filter 'FailedUpload-*.json' -File |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -Skip 4 |
            Remove-Item -Force

        Start-Transcript -LiteralPath $script:TranscriptPath -Force | Out-Null
        $script:TranscriptStarted = $true
        $script:LocalStorageReady = $true
    }
    catch {
        Add-TelemetryError -Operation 'StartTranscript' -ErrorRecord $_
    }
}

function Test-SecureLocalStorage {
    [CmdletBinding()]
    param()

    if (-not $script:LocalStorageReady -or
        -not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        return $false
    }

    $directory = Get-Item -LiteralPath $LogDirectory -Force
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }

    $acl = Get-Acl -LiteralPath $LogDirectory
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }

    $allowedSids = @(
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid, $null
        ).Value
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
        ).Value
    )
    $unexpectedAllow = @($acl.Access | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value -notin $allowedSids
    })

    return $unexpectedAllow.Count -eq 0
}

function Get-OrCreateExecutionState {
    [CmdletBinding()]
    param()

    $mutex = $null
    $lockTaken = $false
    try {
        $mutex = [Threading.Mutex]::new($false, 'Global\IntuneDeploymentTelemetryRegistry')
        try {
            $lockTaken = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
        }
        catch [Threading.AbandonedMutexException] {
            # Ownership transfers to this thread when an abandoned mutex is observed.
            $lockTaken = $true
        }
        if (-not $lockTaken) {
            throw 'Timed out waiting for the telemetry registry lock.'
        }

        if (-not (Test-Path -LiteralPath $RegistryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }

        $properties = Get-ItemProperty -LiteralPath $RegistryPath
        $firstExecution = Get-PropertyValue -InputObject $properties `
            -Name 'FirstExecutionTimestampUTC'
        $correlationId = Get-PropertyValue -InputObject $properties `
            -Name 'CorrelationId'

        if ([string]::IsNullOrWhiteSpace([string]$firstExecution)) {
            $firstExecution = ConvertTo-UtcIso8601 -Value ([datetime]::UtcNow)
            New-ItemProperty -LiteralPath $RegistryPath -Name 'FirstExecutionTimestampUTC' `
                -Value $firstExecution -PropertyType String -Force | Out-Null
        }

        if ([string]::IsNullOrWhiteSpace([string]$correlationId)) {
            $correlationId = [guid]::NewGuid().ToString()
            New-ItemProperty -LiteralPath $RegistryPath -Name 'CorrelationId' `
                -Value $correlationId -PropertyType String -Force | Out-Null
        }

        # ScriptVersion describes the latest executing version; the first timestamp is immutable.
        New-ItemProperty -LiteralPath $RegistryPath -Name 'ScriptVersion' `
            -Value $ScriptVersion -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $RegistryPath -Name 'LastExecutionTimestampUTC' `
            -Value (ConvertTo-UtcIso8601 -Value ([datetime]::UtcNow)) `
            -PropertyType String -Force | Out-Null

        return [pscustomobject]@{
            FirstExecutionTimestampUtc = [string]$firstExecution
            CorrelationId              = [string]$correlationId
            RegistryWriteSuccess       = $true
        }
    }
    catch {
        Add-TelemetryError -Operation 'InitializeRegistryState' -ErrorRecord $_
        return [pscustomobject]@{
            FirstExecutionTimestampUtc = $null
            CorrelationId              = [guid]::NewGuid().ToString()
            RegistryWriteSuccess       = $false
        }
    }
    finally {
        if ($lockTaken -and $null -ne $mutex) {
            $mutex.ReleaseMutex()
        }
        if ($null -ne $mutex) {
            $mutex.Dispose()
        }
    }
}

function Get-DsRegStatus {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        AzureAdJoined   = $false
        AzureAdDeviceId = $null
        TenantId        = $null
        UserUPN         = $null
    }

    $output = & "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "dsregcmd.exe exited with code $LASTEXITCODE."
    }

    foreach ($line in $output) {
        if ($line -match '^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$') {
            $result.AzureAdJoined = $Matches[1] -eq 'YES'
        }
        elseif ($line -match '^\s*DeviceId\s*:\s*([0-9a-fA-F-]{36})\s*$') {
            $result.AzureAdDeviceId = $Matches[1]
        }
        elseif ($line -match '^\s*TenantId\s*:\s*([0-9a-fA-F-]{36})\s*$') {
            $result.TenantId = $Matches[1]
        }
        elseif ($line -match '^\s*UserEmail\s*:\s*(.+?)\s*$') {
            $result.UserUPN = $Matches[1]
        }
    }

    return [pscustomobject]$result
}

function Get-MdmEnrollment {
    [CmdletBinding()]
    param()

    $enrollmentRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    $candidates = @()

    if (Test-Path -LiteralPath $enrollmentRoot) {
        foreach ($key in Get-ChildItem -LiteralPath $enrollmentRoot -ErrorAction Stop) {
            try {
                $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                $providerId = Get-PropertyValue -InputObject $item -Name 'ProviderID'
                $upn = Get-PropertyValue -InputObject $item -Name 'UPN'
                $discoveryService = Get-PropertyValue -InputObject $item `
                    -Name 'DiscoveryServiceFullURL'
                if ($providerId -or $upn -or $discoveryService) {
                    $firstSync = Get-ItemProperty `
                        -LiteralPath (Join-Path $key.PSPath 'FirstSync') `
                        -ErrorAction SilentlyContinue
                    $enrollmentDate = @(
                        Get-PropertyValue -InputObject $item -Name 'EnrollmentDate'
                        Get-PropertyValue -InputObject $item -Name 'EnrollmentTime'
                        Get-PropertyValue -InputObject $firstSync -Name 'FirstSyncTime'
                    ) | Where-Object {
                        $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)
                    } | Select-Object -First 1

                    $candidates += [pscustomobject]@{
                        EnrollmentId       = $key.PSChildName
                        ProviderId         = [string]$providerId
                        UserUPN            = [string]$upn
                        TenantId           = [string](Get-PropertyValue -InputObject $item -Name 'AADTenantID')
                        EnrollmentType     = Get-PropertyValue -InputObject $item -Name 'EnrollmentType'
                        EnrollmentState    = Get-PropertyValue -InputObject $item -Name 'EnrollmentState'
                        EntDMID            = [string](Get-PropertyValue -InputObject $item -Name 'EntDMID')
                        DiscoveryService   = [string]$discoveryService
                        EnrollmentDateUtc  = ConvertTo-OptionalUtcIso8601 -Value $enrollmentDate
                    }
                }
            }
            catch {
                Add-TelemetryError -Operation ('ReadEnrollment:{0}' -f $key.PSChildName) -ErrorRecord $_
            }
        }
    }

    $selected = $candidates |
        Sort-Object @{ Expression = { $_.ProviderId -match 'MS DM Server|Intune' }; Descending = $true },
                    @{ Expression = { -not [string]::IsNullOrWhiteSpace($_.EntDMID) }; Descending = $true } |
        Select-Object -First 1

    if ($null -eq $selected) {
        return [pscustomobject]@{
            Status             = 'NotDiscovered'
            EnrollmentId       = $null
            ManagedDeviceId    = $null
            EnrollmentDateUtc  = $null
            UserUPN            = $null
            TenantId           = $null
            ProviderId         = $null
            EnrollmentType     = $null
            EnrollmentState    = $null
        }
    }

    $status = if ($selected.EnrollmentState -eq 1) { 'Enrolled' } else { 'EnrollmentDiscovered' }
    return [pscustomobject]@{
        Status             = $status
        EnrollmentId       = $selected.EnrollmentId
        ManagedDeviceId    = $selected.EntDMID
        EnrollmentDateUtc  = $selected.EnrollmentDateUtc
        UserUPN            = $selected.UserUPN
        TenantId           = $selected.TenantId
        ProviderId         = $selected.ProviderId
        EnrollmentType     = $selected.EnrollmentType
        EnrollmentState    = $selected.EnrollmentState
    }
}

function Get-MdmScheduledTask {
    [CmdletBinding()]
    param()

    $tasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' `
        -ErrorAction SilentlyContinue
    $result = foreach ($task in $tasks) {
        try {
            $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
            [pscustomobject]@{
                TaskName          = $task.TaskName
                TaskPath          = $task.TaskPath
                State             = [string]$task.State
                LastRunTimeUtc    = if ($info.LastRunTime -is [datetime] -and
                    $info.LastRunTime.Year -ge 2000) {
                    ConvertTo-UtcIso8601 -Value $info.LastRunTime
                } else { $null }
                NextRunTimeUtc    = if ($info.NextRunTime -is [datetime] -and
                    $info.NextRunTime.Year -ge 2000) {
                    ConvertTo-UtcIso8601 -Value $info.NextRunTime
                } else { $null }
                LastTaskResult    = $info.LastTaskResult
                NumberOfMissedRuns = $info.NumberOfMissedRuns
            }
        }
        catch {
            Add-TelemetryError -Operation ('ReadScheduledTask:{0}' -f $task.TaskName) -ErrorRecord $_
        }
    }

    return @($result)
}

function Get-MdmEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory)]
        [int]$MaximumEvents,

        [Parameter(Mandatory)]
        [int]$MessageEventLimit
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $MdmAdminLog
            StartTime = $StartTimeUtc.ToLocalTime()
        } -MaxEvents $MaximumEvents -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound|NoMatchingLogsFound') {
            return @()
        }
        throw
    }

    $eventIndex = 0
    $result = foreach ($eventRecord in $events) {
        $eventIndex++
        $activityId = $null
        try {
            $xml = [xml]$eventRecord.ToXml()
            $correlation = Get-PropertyValue -InputObject $xml.Event.System `
                -Name 'Correlation'
            $activityId = [string](Get-PropertyValue -InputObject $correlation `
                -Name 'ActivityID')
        }
        catch {
            Add-TelemetryError -Operation ('ParseMdmEventXml:{0}' -f $eventRecord.RecordId) -ErrorRecord $_
        }

        $message = $null
        if ($eventIndex -le $MessageEventLimit) {
            try {
                $message = $eventRecord.FormatDescription()
            }
            catch {
                Add-TelemetryError -Operation ('FormatMdmEvent:{0}' -f $eventRecord.RecordId) -ErrorRecord $_
            }
        }

        if ($message -and $message.Length -gt 512) {
            $message = $message.Substring(0, 512)
        }

        [pscustomobject]@{
            TimeCreatedUtc = ConvertTo-UtcIso8601 -Value $eventRecord.TimeCreated
            EventId        = $eventRecord.Id
            Level          = $eventRecord.LevelDisplayName
            RecordId       = $eventRecord.RecordId
            ActivityId     = $activityId
            Message        = $message
        }
    }

    return @($result)
}

function Get-EstimatedMdmCycle {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Events,

        [Parameter()]
        [Nullable[datetime]]$SinceUtc,

        [Parameter(Mandatory)]
        [datetime]$WindowStartUtc,

        [Parameter(Mandatory)]
        [bool]$EventsTruncated,

        [Parameter()]
        [Nullable[datetime]]$OldestRetainedEventUtc
    )

    if ($null -eq $SinceUtc) {
        return [pscustomobject]@{
            Count  = $null
            Method = 'AssignmentTimestampNotProvided'
        }
    }

    $since = [datetime]$SinceUtc
    if ($since -lt $WindowStartUtc) {
        return [pscustomobject]@{
            Count  = $null
            Method = 'AssignmentOlderThanEventWindow'
        }
    }

    $eligible = @($Events | Where-Object {
        [datetime]::Parse($_.TimeCreatedUtc, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind) -ge $since
    } | Sort-Object TimeCreatedUtc)

    if ($eligible.Count -eq 0) {
        return [pscustomobject]@{
            Count  = 0
            Method = if ($EventsTruncated) {
                'NoMatchingEventsInTruncatedSample'
            } else {
                'NoDMEDPEventsAfterAssignment'
            }
        }
    }

    if ($EventsTruncated -and
        ($null -eq $OldestRetainedEventUtc -or
        [datetime]$OldestRetainedEventUtc -gt $since)) {
        return [pscustomobject]@{
            Count  = $null
            Method = 'EventSampleDoesNotCoverAssignment'
        }
    }

    $activityIds = @($eligible |
        ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.ActivityId)) {
                ([string]$_.ActivityId).Trim('{}').ToLowerInvariant()
            }
        } |
        Where-Object { $_ -and $_ -ne [guid]::Empty.ToString() } |
        Select-Object -Unique)

    if ($activityIds.Count -gt 0) {
        return [pscustomobject]@{
            Count  = $activityIds.Count
            Method = 'DistinctDMEDPActivityIds'
        }
    }

    # Fallback: events separated by at least 15 minutes are treated as distinct sessions.
    $cycles = 0
    $previous = $null
    foreach ($eventRecord in $eligible) {
        $current = [datetime]::Parse(
            $eventRecord.TimeCreatedUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        if ($null -eq $previous -or ($current - $previous).TotalMinutes -ge 15) {
            $cycles++
        }
        $previous = $current
    }

    return [pscustomobject]@{
        Count  = $cycles
        Method = 'FifteenMinuteEventClusters'
    }
}

function Get-PendingRestartState {
    [CmdletBinding()]
    param()

    $reasons = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('ComponentBasedServicing')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('WindowsUpdate')
    }

    $sessionManager = Get-ItemProperty `
        -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($null -ne $sessionManager -and $sessionManager.PendingFileRenameOperations) {
        $reasons.Add('PendingFileRenameOperations')
    }

    return [pscustomobject]@{
        IsPending = $reasons.Count -gt 0
        Reasons   = @($reasons)
    }
}

function Get-InteractiveUser {
    [CmdletBinding()]
    param()

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    return [string]$computerSystem.UserName
}

function Get-CertificateSha256Thumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Certificate.RawData)
        return ([BitConverter]::ToString($hash)).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Test-ClientAuthenticationEku {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $clientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
    $ekuExtension = $Certificate.Extensions |
        Where-Object {
            $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        } |
        Select-Object -First 1

    return $null -ne $ekuExtension -and
        @($ekuExtension.EnhancedKeyUsages | Where-Object {
            $_.Value -eq $clientAuthenticationOid
        }).Count -gt 0
}

function Get-TelemetryClientCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$TrustedIssuerSha256Thumbprints
    )

    $now = [datetime]::UtcNow
    $trustedIssuerMap = @{}

    foreach ($thumbprint in $TrustedIssuerSha256Thumbprints) {
        $normalizedThumbprint = ($thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($normalizedThumbprint -notmatch '^[0-9A-F]{64}$') {
            throw 'Each trusted issuer requires a 64-character SHA-256 thumbprint.'
        }
        $trustedIssuerMap[$normalizedThumbprint] = $true
    }

    if ($trustedIssuerMap.Count -eq 0) {
        throw 'Configure at least one trusted issuing certificate authority.'
    }

    $certificates = [System.Collections.Generic.List[object]]::new()
    foreach ($certificate in @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My')) {
        if (-not $certificate.HasPrivateKey -or
            $certificate.NotBefore.ToUniversalTime() -gt $now -or
            $certificate.NotAfter.ToUniversalTime() -le $now -or
            -not (Test-ClientAuthenticationEku -Certificate $certificate)) {
            continue
        }

        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.RevocationMode =
                [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            if (-not $chain.Build($certificate) -or $chain.ChainElements.Count -lt 2) {
                continue
            }

            $issuerCertificate = $chain.ChainElements[1].Certificate
            $issuerThumbprint = Get-CertificateSha256Thumbprint -Certificate $issuerCertificate
            if ($trustedIssuerMap.ContainsKey($issuerThumbprint)) {
                $certificates.Add($certificate)
            }
        }
        finally {
            $chain.Dispose()
        }
    }

    $certificates = @($certificates | Sort-Object NotBefore, NotAfter -Descending)

    if ($certificates.Count -eq 0) {
        throw 'No valid client-authentication certificate from a trusted issuing CA was found in LocalMachine\My.'
    }

    return $certificates[0]
}

function Get-DirectIngestionAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$TenantId,

        [Parameter(Mandatory)]
        [guid]$ClientId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds
    )

    $tokenEndpoint = [uri](
        'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
    )
    $tokenRequest = @{
        client_id     = $ClientId.ToString()
        client_secret = $ClientSecret
        scope         = 'https://monitor.azure.com//.default'
        grant_type    = 'client_credentials'
    }

    $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post `
        -ContentType 'application/x-www-form-urlencoded' -Body $tokenRequest `
        -TimeoutSec $TimeoutSeconds -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$response.access_token)) {
        throw 'Microsoft Entra returned no access token for direct ingestion.'
    }

    return [string]$response.access_token
}

function Send-TelemetryBrokerData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$Uri,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [byte[]]$Body,

        [Parameter(Mandatory)]
        [int]$RetryCount,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [guid]$RequestId
    )

    $attempt = 0
    $lastAttempt = 0
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        $lastAttempt = $attempt
        $headers = @{
            'X-Correlation-ID' = $RequestId.ToString()
        }

        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $headers `
                -Certificate $Certificate -ContentType 'application/json' `
                -Body $Body -UseBasicParsing `
                -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            if ($response.StatusCode -in @(200, 202)) {
                return [pscustomobject]@{
                    Success    = $true
                    StatusCode = [int]$response.StatusCode
                    Attempts   = $attempt
                }
            }
            throw "Unexpected HTTP status code $($response.StatusCode)."
        }
        catch {
            Add-TelemetryError -Operation ('BrokerUploadAttempt:{0}' -f $attempt) -ErrorRecord $_
            $statusCode = $null
            $response = Get-PropertyValue -InputObject $_.Exception -Name 'Response'
            $responseStatus = Get-PropertyValue -InputObject $response -Name 'StatusCode'
            if ($null -ne $responseStatus) {
                $statusCode = [int]$responseStatus
            }
            if ($statusCode -in @(400, 401, 403, 404, 409, 413, 422)) {
                break
            }
            if ($attempt -eq $RetryCount) {
                break
            }

            $delaySeconds = [Math]::Min(30, [Math]::Pow(2, $attempt - 1)) +
                (Get-Random -Minimum 0 -Maximum 1000) / 1000
            Start-Sleep -Milliseconds ([int]($delaySeconds * 1000))
        }
    }

    return [pscustomobject]@{
        Success    = $false
        StatusCode = $null
        Attempts   = $lastAttempt
    }
}

function Send-TelemetryDirectData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$LogsIngestionEndpoint,

        [Parameter(Mandatory)]
        [string]$DcrImmutableId,

        [Parameter(Mandatory)]
        [string]$StreamName,

        [Parameter(Mandatory)]
        [guid]$TenantId,

        [Parameter(Mandatory)]
        [guid]$ClientId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [Parameter(Mandatory)]
        [byte[]]$Body,

        [Parameter(Mandatory)]
        [int]$RetryCount,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds
    )

    $escapedDcrId = [uri]::EscapeDataString($DcrImmutableId)
    $escapedStreamName = [uri]::EscapeDataString($StreamName)
    $requestUri = [uri](
        '{0}/dataCollectionRules/{1}/streams/{2}?api-version=2023-01-01' -f
        $LogsIngestionEndpoint.AbsoluteUri.TrimEnd('/'),
        $escapedDcrId,
        $escapedStreamName
    )

    $lastAttempt = 0
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        $lastAttempt = $attempt
        try {
            $accessToken = Get-DirectIngestionAccessToken -TenantId $TenantId `
                -ClientId $ClientId -ClientSecret $ClientSecret `
                -TimeoutSeconds $TimeoutSeconds
            $headers = @{
                Authorization = "Bearer $accessToken"
            }
            $response = Invoke-WebRequest -Uri $requestUri -Method Post `
                -Headers $headers -ContentType 'application/json' `
                -Body $Body -UseBasicParsing -TimeoutSec $TimeoutSeconds `
                -ErrorAction Stop
            if ($response.StatusCode -in @(200, 202, 204)) {
                return [pscustomobject]@{
                    Success    = $true
                    StatusCode = [int]$response.StatusCode
                    Attempts   = $attempt
                }
            }
            throw "Unexpected HTTP status code $($response.StatusCode)."
        }
        catch {
            Add-TelemetryError -Operation ('DirectLogsUploadAttempt:{0}' -f $attempt) `
                -ErrorRecord $_
            $statusCode = $null
            $errorResponse = Get-PropertyValue -InputObject $_.Exception -Name 'Response'
            $responseStatus = Get-PropertyValue -InputObject $errorResponse -Name 'StatusCode'
            if ($null -ne $responseStatus) {
                $statusCode = [int]$responseStatus
            }
            if ($statusCode -in @(400, 401, 403, 404, 409, 413, 422)) {
                break
            }
            if ($attempt -eq $RetryCount) {
                break
            }

            $delaySeconds = [Math]::Min(30, [Math]::Pow(2, $attempt - 1)) +
                (Get-Random -Minimum 0 -Maximum 1000) / 1000
            Start-Sleep -Milliseconds ([int]($delaySeconds * 1000))
        }
        finally {
            $accessToken = $null
        }
    }

    return [pscustomobject]@{
        Success    = $false
        StatusCode = $null
        Attempts   = $lastAttempt
    }
}

function ConvertTo-DirectIngestionPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Collections.IDictionary]$Payload,

        [Parameter(Mandatory)]
        [bool]$IncludeSensitiveData
    )

    if (-not $IncludeSensitiveData) {
        $Payload.Remove('UserUPN')
        $Payload.Remove('CurrentLoggedOnUser')
        foreach ($event in @($Payload.MDMEvents)) {
            $event.PSObject.Properties.Remove('Message')
        }
    }

    $Payload.Add(
        'BrokerReceivedTimestampUtc',
        (ConvertTo-UtcIso8601 -Value ([datetime]::UtcNow))
    )
    $Payload.Add('BrokerRequestId', $Payload.ExecutionId)
    $Payload.Add('ClientCertificateThumbprint', $null)
    $Payload.Add('ClientCertificateIssuerThumbprint', $null)
    return $Payload
}

function New-TelemetryPayload {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates an in-memory payload and does not change system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ExecutionState,

        [Parameter(Mandatory)]
        [datetime]$CurrentExecutionUtc,

        [Parameter()]
        [Nullable[datetime]]$PolicyAssignmentTimestampUtc,

        [Parameter(Mandatory)]
        [int]$MdmEventLookbackHours,

        [Parameter(Mandatory)]
        [int]$MdmMaximumEvents
    )

    $operatingSystem = Invoke-TelemetryOperation -Name 'GetOperatingSystem' -Operation {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    $dsreg = Invoke-TelemetryOperation -Name 'GetDsRegStatus' -Operation {
        Get-DsRegStatus
    }
    $enrollment = Invoke-TelemetryOperation -Name 'GetMdmEnrollment' -Operation {
        Get-MdmEnrollment
    }
    $tasks = @(Invoke-TelemetryOperation -Name 'GetMdmScheduledTasks' -Operation {
        Get-MdmScheduledTask
    } -Default @())
    $tasks = @($tasks | Sort-Object LastRunTimeUtc -Descending)
    $tasksTruncated = $false
    while ($tasks.Count -gt 0) {
        $taskJson = ConvertTo-Json -InputObject @($tasks) -Depth 5 -Compress
        if ([Text.Encoding]::UTF8.GetByteCount($taskJson) -le 28672) {
            break
        }
        $tasksTruncated = $true
        $tasks = @($tasks | Select-Object -First ($tasks.Count - 1))
    }
    $eventWindowStartUtc = [datetime]::UtcNow.AddHours(-$MdmEventLookbackHours)
    $cycleEventLimit = 2000
    $allEvents = @(Invoke-TelemetryOperation -Name 'GetMdmEvents' -Operation {
        Get-MdmEvent -StartTimeUtc $eventWindowStartUtc `
            -MaximumEvents ($cycleEventLimit + 1) `
            -MessageEventLimit $MdmMaximumEvents
    } -Default @())
    $cycleEventsTruncated = $allEvents.Count -gt $cycleEventLimit
    if ($cycleEventsTruncated) {
        $allEvents = @($allEvents | Select-Object -First $cycleEventLimit)
    }
    $oldestCycleEventUtc = $null
    if ($allEvents.Count -gt 0) {
        $oldestCycleEventUtc = [datetime]::Parse(
            $allEvents[-1].TimeCreatedUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    $events = @($allEvents | Select-Object -First $MdmMaximumEvents)
    $eventsTruncated = $allEvents.Count -gt $MdmMaximumEvents
    while ($events.Count -gt 0) {
        $eventJson = ConvertTo-Json -InputObject @($events) -Depth 5 -Compress
        if ([Text.Encoding]::UTF8.GetByteCount($eventJson) -le 28672) {
            break
        }
        $eventsTruncated = $true
        $events = @($events | Select-Object -First ($events.Count - 1))
    }
    $pendingRestart = Invoke-TelemetryOperation -Name 'GetPendingRestartState' -Operation {
        Get-PendingRestartState
    }
    $interactiveUser = Invoke-TelemetryOperation -Name 'GetInteractiveUser' -Operation {
        Get-InteractiveUser
    }

    $lastBootUtc = $null
    $uptimeHours = $null
    $osVersion = $null
    $buildNumber = $null
    if ($null -ne $operatingSystem) {
        $lastBoot = if ($operatingSystem.LastBootUpTime -is [datetime]) {
            $operatingSystem.LastBootUpTime.ToUniversalTime()
        } else {
            [Management.ManagementDateTimeConverter]::ToDateTime(
                [string]$operatingSystem.LastBootUpTime
            ).ToUniversalTime()
        }
        $lastBootUtc = ConvertTo-UtcIso8601 -Value $lastBoot
        $uptimeHours = [Math]::Round(([datetime]::UtcNow - $lastBoot).TotalHours, 2)
        $osVersion = [string]$operatingSystem.Version
        $buildNumber = [string]$operatingSystem.BuildNumber
    }

    $lastTaskSync = $tasks |
        Where-Object { $_.LastRunTimeUtc } |
        Sort-Object LastRunTimeUtc -Descending |
        Select-Object -First 1
    $lastEventSync = $events |
        Sort-Object TimeCreatedUtc -Descending |
        Select-Object -First 1
    $lastKnownSync = @(
        if ($lastTaskSync) { $lastTaskSync.LastRunTimeUtc }
        if ($lastEventSync) { $lastEventSync.TimeCreatedUtc }
    ) | Sort-Object -Descending | Select-Object -First 1

    $assignment = if ($null -ne $PolicyAssignmentTimestampUtc -and
        [datetime]$PolicyAssignmentTimestampUtc -gt [datetime]::MinValue) {
        ([datetime]$PolicyAssignmentTimestampUtc).ToUniversalTime()
    } else {
        $null
    }
    $cycles = Get-EstimatedMdmCycle -Events $allEvents -SinceUtc $assignment `
        -WindowStartUtc $eventWindowStartUtc `
        -EventsTruncated $cycleEventsTruncated `
        -OldestRetainedEventUtc $oldestCycleEventUtc
    $firstExecution = ConvertTo-OptionalUtcIso8601 -Value $ExecutionState.FirstExecutionTimestampUtc
    $assignmentLatency = if ($null -ne $assignment -and $null -ne $firstExecution) {
        $firstExecutionDate = [datetime]::Parse(
            $firstExecution,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        [Math]::Round(($firstExecutionDate - $assignment).TotalMinutes, 2)
    } else {
        $null
    }

    $userUpn = if ($dsreg -and $dsreg.UserUPN) {
        $dsreg.UserUPN
    } elseif ($enrollment) {
        $enrollment.UserUPN
    } else {
        $null
    }
    $tenantId = if ($dsreg -and $dsreg.TenantId) {
        $dsreg.TenantId
    } elseif ($enrollment) {
        $enrollment.TenantId
    } else {
        $null
    }
    $errorSnapshot = Get-TelemetryErrorSnapshot

    return [ordered]@{
        TimestampUtc                  = ConvertTo-UtcIso8601 -Value $CurrentExecutionUtc
        DeviceName                   = $env:COMPUTERNAME
        DeviceId                     = if ($enrollment) { $enrollment.EnrollmentId } else { $null }
        AzureAdDeviceId               = if ($dsreg) { $dsreg.AzureAdDeviceId } else { $null }
        ManagedDeviceId               = if ($enrollment) { $enrollment.ManagedDeviceId } else { $null }
        TenantDirectoryId             = $tenantId
        UserUPN                       = $userUpn
        CurrentLoggedOnUser           = $interactiveUser
        FirstExecutionTimestampUtc    = $ExecutionState.FirstExecutionTimestampUtc
        CurrentExecutionTimestampUtc  = ConvertTo-UtcIso8601 -Value $CurrentExecutionUtc
        AssignmentTimestampUtc        = if ($assignment) { ConvertTo-UtcIso8601 -Value $assignment } else { $null }
        AssignmentToExecutionMinutes  = $assignmentLatency
        LastBootTimeUtc               = $lastBootUtc
        UptimeHours                   = $uptimeHours
        OSVersion                     = $osVersion
        BuildNumber                   = $buildNumber
        RestartPending                = if ($pendingRestart) { $pendingRestart.IsPending } else { $null }
        RestartPendingReasons         = if ($pendingRestart) { @($pendingRestart.Reasons) } else { @() }
        MDMEnrollmentStatus           = if ($enrollment) { $enrollment.Status } else { 'Unknown' }
        MDMEnrollmentDateUtc          = if ($enrollment) { $enrollment.EnrollmentDateUtc } else { $null }
        MDMProviderId                 = if ($enrollment) { $enrollment.ProviderId } else { $null }
        MDMEnrollmentType             = if ($enrollment) {
            [string]$enrollment.EnrollmentType
        } else { $null }
        MDMEnrollmentState            = if ($enrollment) {
            [string]$enrollment.EnrollmentState
        } else { $null }
        LastKnownMDMSync              = $lastKnownSync
        EstimatedMDMCheckInCycles     = $cycles.Count
        MDMCheckInCycleMethod         = $cycles.Method
        MDMEventWindowStartUtc         = ConvertTo-UtcIso8601 -Value $eventWindowStartUtc
        MDMEventsTruncated             = $eventsTruncated
        MDMCycleEventsTruncated        = $cycleEventsTruncated
        MDMCycleOldestRetainedUtc      = if ($oldestCycleEventUtc) {
            ConvertTo-UtcIso8601 -Value $oldestCycleEventUtc
        } else { $null }
        MDMScheduledTasks             = $tasks
        MDMScheduledTasksTruncated    = $tasksTruncated
        MDMEvents                     = $events
        CorrelationId                 = $ExecutionState.CorrelationId
        ExecutionId                   = [guid]::NewGuid().ToString()
        ScriptVersion                 = $ScriptVersion
        RegistryWriteSuccess          = $ExecutionState.RegistryWriteSuccess
        BrokerUploadSuccess           = $true
        Errors                        = $errorSnapshot.Errors
        ErrorsTruncatedCount          = $errorSnapshot.TruncatedCount
    }
}

$exitCode = 0
Initialize-LocalLogging
Write-Output "Starting Intune deployment telemetry version $ScriptVersion."

try {
    $currentExecutionUtc = [datetime]::UtcNow
    if ($EventLookbackHours -lt 1 -or $EventLookbackHours -gt 168) {
        throw 'EventLookbackHours must be between 1 and 168.'
    }
    if ($MaximumMdmEvents -lt 1 -or $MaximumMdmEvents -gt 100) {
        throw 'MaximumMdmEvents must be between 1 and 100.'
    }
    if ($UploadRetryCount -lt 1 -or $UploadRetryCount -gt 10) {
        throw 'UploadRetryCount must be between 1 and 10.'
    }
    if ($UploadTimeoutSeconds -lt 5 -or $UploadTimeoutSeconds -gt 120) {
        throw 'UploadTimeoutSeconds must be between 5 and 120.'
    }
    if ($AssignmentTimestampUtc -notmatch '(?i)(Z|[+-]\d{2}:\d{2})$') {
        throw 'Configure AssignmentTimestampUtc as ISO 8601 with Z or an explicit UTC offset.'
    }
    $parsedAssignment = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse(
        $AssignmentTimestampUtc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsedAssignment
    )) {
        throw 'AssignmentTimestampUtc is not a valid ISO 8601 timestamp.'
    }
    if (-not $SkipUpload) {
        if ($UploadMode -notin @('Broker', 'DirectLogs')) {
            throw "UploadMode must be 'Broker' or 'DirectLogs'."
        }
        if ($UploadMode -eq 'Broker') {
            $parsedBrokerUri = $null
            if (-not [uri]::TryCreate($BrokerUri, [UriKind]::Absolute, [ref]$parsedBrokerUri) -or
                $parsedBrokerUri.Scheme -ne 'https' -or
                $parsedBrokerUri.AbsolutePath.TrimEnd('/') -ne '/api/telemetry') {
                throw 'Configure BrokerUri as an HTTPS /api/telemetry endpoint.'
            }
        }
        else {
            $parsedDirectEndpoint = $null
            if (-not [uri]::TryCreate(
                $DirectLogsIngestionEndpoint,
                [UriKind]::Absolute,
                [ref]$parsedDirectEndpoint
            ) -or $parsedDirectEndpoint.Scheme -ne 'https' -or
                -not [string]::IsNullOrEmpty($parsedDirectEndpoint.UserInfo) -or
                -not [string]::IsNullOrEmpty($parsedDirectEndpoint.Query) -or
                -not [string]::IsNullOrEmpty($parsedDirectEndpoint.Fragment) -or
                $parsedDirectEndpoint.Host -notmatch '(?i)(^|\.)ingest\.monitor\.azure\.com$') {
                throw 'Configure DirectLogsIngestionEndpoint as an Azure Monitor HTTPS ingestion URI without credentials, query, or fragment.'
            }
            $parsedTenantId = [guid]::Empty
            if (-not [guid]::TryParse($DirectTenantId, [ref]$parsedTenantId)) {
                throw 'DirectTenantId must be a GUID.'
            }
            $parsedClientId = [guid]::Empty
            if (-not [guid]::TryParse($DirectClientId, [ref]$parsedClientId)) {
                throw 'DirectClientId must be a GUID.'
            }
            if ($DirectDcrImmutableId -notmatch '^dcr-[0-9A-Za-z]+$') {
                throw 'DirectDcrImmutableId must be a valid immutable DCR identifier.'
            }
            if ($DirectStreamName -notmatch '^Custom-[A-Za-z][A-Za-z0-9_]{0,127}$') {
                throw 'DirectStreamName must be a valid custom DCR stream name.'
            }
            if ([string]::IsNullOrWhiteSpace($DirectClientSecret) -or
                $DirectClientSecret -eq '<APP-REGISTRATION-CLIENT-SECRET>' -or
                $DirectClientSecret.Length -gt 4096) {
                throw 'Configure DirectClientSecret with the POC App Registration secret.'
            }
        }
    }
    $assignmentValue = [Nullable[datetime]]$parsedAssignment.UtcDateTime
    $state = Get-OrCreateExecutionState
    $payload = New-TelemetryPayload -ExecutionState $state `
        -CurrentExecutionUtc $currentExecutionUtc `
        -PolicyAssignmentTimestampUtc $assignmentValue `
        -MdmEventLookbackHours $EventLookbackHours `
        -MdmMaximumEvents $MaximumMdmEvents

    if ($SkipUpload) {
        $payload.BrokerUploadSuccess = $false
        Write-Output ('Upload skipped. ExecutionId={0}; Device={1}; Errors={2}' -f `
            $payload.ExecutionId, $payload.DeviceName, $script:Errors.Count)
    }
    else {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($UploadMode -eq 'Broker') {
            $certificate = Get-TelemetryClientCertificate `
                -TrustedIssuerSha256Thumbprints $TrustedIssuerCaSha256Thumbprints
            $json = ConvertTo-Json -InputObject $payload -Depth 8 -Compress
            $body = [Text.Encoding]::UTF8.GetBytes($json)
            $upload = Send-TelemetryBrokerData -Uri $parsedBrokerUri `
                -Certificate $certificate -Body $body `
                -RetryCount $UploadRetryCount `
                -TimeoutSeconds $UploadTimeoutSeconds `
                -RequestId ([guid]$payload.ExecutionId)
        }
        else {
            $payload = ConvertTo-DirectIngestionPayload -Payload $payload `
                -IncludeSensitiveData $DirectIncludeSensitiveData
            $directJson = ConvertTo-Json -InputObject @($payload) -Depth 8 -Compress
            $body = [Text.Encoding]::UTF8.GetBytes($directJson)
            $upload = Send-TelemetryDirectData `
                -LogsIngestionEndpoint $parsedDirectEndpoint `
                -DcrImmutableId $DirectDcrImmutableId `
                -StreamName $DirectStreamName `
                -TenantId $parsedTenantId `
                -ClientId $parsedClientId `
                -ClientSecret $DirectClientSecret `
                -Body $body `
                -RetryCount $UploadRetryCount `
                -TimeoutSeconds $UploadTimeoutSeconds
        }

        if (-not $upload.Success) {
            $payload.BrokerUploadSuccess = $false
            $errorSnapshot = Get-TelemetryErrorSnapshot
            $payload.Errors = $errorSnapshot.Errors
            $payload.ErrorsTruncatedCount = $errorSnapshot.TruncatedCount
            if (Test-SecureLocalStorage) {
                $failurePath = Join-Path $LogDirectory (
                    'FailedUpload-{0}.json' -f $payload.ExecutionId
                )
                ConvertTo-Json -InputObject @($payload) -Depth 8 |
                    Set-Content -LiteralPath $failurePath -Encoding UTF8 -Force
                throw "$UploadMode upload failed after $($upload.Attempts) attempts. Payload saved to $failurePath."
            }
            throw "$UploadMode upload failed after $($upload.Attempts) attempts. Local persistence was disabled because secure storage validation failed."
        }

        Write-Output ('Telemetry accepted. Mode={0}; ExecutionId={1}; HTTP={2}; Attempts={3}' -f `
            $UploadMode, $payload.ExecutionId, $upload.StatusCode, $upload.Attempts)
    }
}
catch {
    Add-TelemetryError -Operation 'Main' -ErrorRecord $_
    Write-Error $_ -ErrorAction Continue
    $exitCode = 1
}
finally {
    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-Warning "Unable to stop transcript: $($_.Exception.Message)"
        }
    }
}

exit $exitCode
