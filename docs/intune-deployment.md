# 🖥️ Intune deployment

## Broker profiles: deploy certificate trust

1. Create a Trusted certificate profile containing the issuing root CA.
2. Assign it to the telemetry device group.
3. Confirm the root is present on pilot devices.

## Broker profiles: deploy the client certificate

Create a device SCEP/PKCS profile as described in
[certificate authentication](certificate-authentication.md). Require Client
Authentication EKU and a non-exportable private key. The subject format is an
organizational choice; authorization is based on the immediate issuing CA.

These two certificate sections apply only to `dev`, `prod`, and `premium`.
For `poc`, do **not** deploy a trusted-root or client-certificate profile. The
absence of a prior device prerequisite is intentional and necessary to
measure Platform Script delivery latency.

## Configure the script

For `dev`, `prod`, and `premium`, configure broker mode:

```powershell
$UploadMode = 'Broker'
$BrokerUri = 'https://<function-app-hostname>/api/telemetry'
$AssignmentTimestampUtc = '2026-08-27T15:00:00Z'
$TrustedIssuerCaSha256Thumbprints = @(
    '<64-character-SHA256-fingerprint>'
)
```

For the minimal Proof of Concept profile, configure direct mode:

```powershell
$UploadMode = 'DirectLogs'
$AssignmentTimestampUtc = '2026-08-28T08:00:00Z'
$DirectTenantId = '<tenant-guid>'
$DirectClientId = '<app-registration-client-id>'
$DirectClientSecret = '<APP-REGISTRATION-CLIENT-SECRET>'
$DirectLogsIngestionEndpoint = 'https://<dcr-endpoint>'
$DirectDcrImmutableId = 'dcr-<immutable-id>'
$DirectStreamName = 'Custom-IntuneDeploymentTelemetry'
$DirectIncludeSensitiveData = $false
```

The direct-mode client secret is created only for the Proof of Concept and is
authorized through RBAC only on its DCR. Embedding it removes any certificate
deployment prerequisite, but anyone who can read the script can use the same
application identity until the credential is revoked or expires.

Direct mode omits UPN, the interactive username, and raw MDM event messages by
default. Set `DirectIncludeSensitiveData` to `$true` only after an explicit
privacy review.

The repository contains a POC-specific template in:

`scripts\intune\poc\Intune-DeploymentTelemetry-POC.ps1`

Store the actual secret in the adjacent ignored file:

`scripts\intune\poc\Intune-DeploymentTelemetry-POC.secret.txt`

Generate the single-file Platform Script immediately before assignment:

```powershell
.\scripts\intune\poc\New-ConfiguredPocPlatformScript.ps1
```

The generator stamps the current UTC time by default. Run it immediately
before uploading and assigning the script. Use `-AssignmentTimestampUtc` only
to reproduce a controlled test with an explicit ISO 8601 timestamp, such as
`2026-08-28T08:00:00Z`. The generator prints the exact UTC value it stamped.

Upload `Intune-DeploymentTelemetry-POC.generated.ps1`. Intune Platform Scripts
don't deploy adjacent files, so the generated file contains the secret and
must remain ignored, local, and protected.

In this manual workflow, `AssignmentToExecutionMinutes` is actually measured
from generation to execution. It therefore includes signing, upload, and
assignment delay. Exact assignment-to-execution measurement requires
automating generation, Graph upload, and assignment in one operation.

Increment `Major.Minor.Build`, sign the final file, and don't modify it after
signing.

## Create the Platform Script

| Intune setting | Value |
|---|---|
| Run this script using the logged-on credentials | No |
| Enforce script signature check | Yes |
| Run script in 64-bit PowerShell host | Yes |

For broker profiles, assign the script only after the certificates are
available. For `poc`, assign the script directly to the disposable POC device
group without any certificate prerequisite.

## Validate broker profiles

- Function broker returns `202`.
- Intune reports script success.
- `IntuneDeploymentTelemetry_CL` receives the device record.
- Selected certificate chains through an authorized issuer fingerprint.
- Application Insights contains no payload body or UPN.

## Validate the POC profile

- The direct DCR endpoint returns `204`.
- `IntuneDeploymentTelemetry_CL` receives the device record.
- `ClientCertificateThumbprint` and
  `ClientCertificateIssuerThumbprint` are empty.
- The App Registration has only **Monitoring Metrics Publisher** on the POC
  DCR.
- UPN, interactive username, and raw event messages are absent while
  `DirectIncludeSensitiveData` remains `$false`.

Platform Scripts normally execute once after success. Use Remediations for
periodic telemetry rather than forcing a successful Platform Script to rerun.
