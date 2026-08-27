# 🖥️ Intune deployment

## 1. Deploy certificate trust

1. Create a Trusted certificate profile containing the issuing root CA.
2. Assign it to the telemetry device group.
3. Confirm the root is present on pilot devices.

## 2. Deploy the client certificate

Create a device SCEP/PKCS profile as described in
[certificate authentication](certificate-authentication.md). Require Client
Authentication EKU and a non-exportable private key. The subject format is an
organizational choice; authorization is based on the immediate issuing CA.

## 3. Configure the script

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
$DirectTenantId = '<tenant-guid>'
$DirectClientId = '<app-registration-client-id>'
$DirectLogsIngestionEndpoint = 'https://<dcr-endpoint>'
$DirectDcrImmutableId = 'dcr-<immutable-id>'
$DirectStreamName = 'Custom-IntuneDeploymentTelemetry'
$DirectApplicationCertificateSha256Thumbprint = '<64-character-SHA256-fingerprint>'
$DirectIncludeSensitiveData = $false
```

The direct-mode certificate is an application credential created only for the
Proof of Concept. It must be present with its RSA private key in
`LocalMachine\My`. The script selects it only by the configured SHA-256
fingerprint; it does not reuse or discover the normal telemetry mTLS
certificate.

Direct mode omits UPN, the interactive username, and raw MDM event messages by
default. Set `DirectIncludeSensitiveData` to `$true` only after an explicit
privacy review.

Increment `Major.Minor.Build`, sign the final file, and don't modify it after
signing.

## 4. Create the Platform Script

| Intune setting | Value |
|---|---|
| Run this script using the logged-on credentials | No |
| Enforce script signature check | Yes |
| Run script in 64-bit PowerShell host | Yes |

Assign the script to the same pilot device group only after certificates are
available.

## 5. Validate

- Function broker returns `202`.
- Intune reports script success.
- `IntuneDeploymentTelemetry_CL` receives the device record.
- Selected certificate chains through an authorized issuer fingerprint.
- Application Insights contains no payload body or UPN.

Platform Scripts normally execute once after success. Use Remediations for
periodic telemetry rather than forcing a successful Platform Script to rerun.
