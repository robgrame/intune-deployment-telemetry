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

Edit only the configuration block:

```powershell
$BrokerUri = 'https://<function-app-hostname>/api/telemetry'
$AssignmentTimestampUtc = '2026-08-27T15:00:00Z'
$TrustedIssuerCaSha256Thumbprints = @(
    '<64-character-SHA256-fingerprint>'
)
```

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
