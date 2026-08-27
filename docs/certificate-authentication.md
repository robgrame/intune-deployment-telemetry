# 🔐 Certificate authentication and validation

## What “the Intune certificate” means

Intune isn't the certificate authority. It deploys a unique client certificate
to each managed Windows device through one of these options:

- Microsoft Cloud PKI;
- SCEP with an Intune Certificate Connector and NDES;
- PKCS certificate profiles with an Intune Certificate Connector.

The issuing CA remains the trust authority. The Azure broker trusts only the
public root certificates explicitly configured at deployment.

## Recommended Intune profile

Create a **device** SCEP or PKCS certificate profile with:

| Setting | Recommended value |
|---|---|
| Certificate store | Computer / Personal (`LocalMachine\My`) |
| Subject name | Any convention approved by the organization |
| Key usage | Digital signature |
| Extended key usage | Client Authentication (`1.3.6.1.5.5.7.3.2`) |
| Key size | 2048-bit or stronger |
| Private key | Non-exportable; hardware-backed where available |
| Validity | Shortest duration compatible with reliable renewal |
| Assignment | Device group used for the telemetry pilot |

Deploy the CA root through an Intune **Trusted certificate** profile before
deploying the client profile.

## Request flow

1. The PowerShell collector searches `Cert:\LocalMachine\My` for certificates:
   - with a private key;
   - with Client Authentication EKU;
   - whose immediate issuing CA subject and SHA-256 fingerprint match the
     configured allowlist.
2. If more than one certificate matches, it selects the certificate with the
   most recent `NotBefore` timestamp, then the latest `NotAfter`.
3. `Invoke-WebRequest -Certificate` performs the TLS client handshake.
4. Azure App Service requires a client certificate and forwards it to the
   Function in `X-ARR-ClientCert`.
5. The broker independently validates the forwarded certificate before
   accepting the payload.

## Broker validation

App Service requests and forwards the client certificate, but Microsoft
explicitly requires application code to validate it. The broker performs:

1. **Header parsing** — reject absent or malformed `X-ARR-ClientCert`.
2. **Validity** — reject certificates outside `NotBefore` / `NotAfter`.
3. **Purpose** — require Client Authentication EKU.
4. **Chain trust** — build with `.NET 10` `CustomRootTrust`, using only the
   configured Intune CA roots.
5. **Issuer authorization** — require the immediate issuing CA certificate's
   SHA-256 fingerprint to be in the configured allowlist.
6. **Payload controls** — enforce size, schema, timestamp, and string limits.
7. **Server ownership** — overwrite broker timestamp, request ID, and
   certificate thumbprint fields before ingestion.

The Function App setting `clientCertMode: Required` blocks requests without a
certificate at the App Service edge. `/api/health` is the only certificate
exclusion and contains no sensitive information.

Revocation validation is deliberately disabled with `NoCheck`. The issuing CA
might publish CRL or OCSP endpoints that aren't reachable from Azure, which
would otherwise reject valid devices. Consequently, revoking an individual
client certificate doesn't immediately block broker access. To contain a
compromise, remove the affected issuing CA fingerprint from the allowlist or
rotate to a new issuing CA.

## Trust-root configuration

`CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64` accepts semicolon-separated,
Base64-encoded DER certificates:

```text
<base64-current-root>;<base64-next-root>
```

Public CA certificates aren't secrets. The setting is nevertheless passed as
a secure Bicep parameter to reduce accidental disclosure and copy/paste.

`CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS` contains the corresponding
authorized immediate issuing CA fingerprints, also separated by semicolons.
These are SHA-256 fingerprints of the CA certificate raw DER bytes, not the
legacy SHA-1 thumbprint commonly displayed by Windows.

Generate the fingerprint with:

```powershell
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    'C:\certificates\IntuneTelemetryIssuingCA.cer'
)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    ([BitConverter]::ToString(
        $sha256.ComputeHash($certificate.RawData)
    )).Replace('-', '')
}
finally {
    $sha256.Dispose()
}
```

## Safe CA rotation

1. Add the next root and issuer SHA-256 fingerprint to the broker while
   retaining the current values.
2. Deploy the next trusted-root and client-certificate profiles through Intune.
3. Verify telemetry from certificates chaining to the next root.
4. Wait until the old certificate population is below the agreed threshold.
5. Remove the old root from the broker.
6. Retire the old Intune certificate profiles and CA according to policy.

Never replace the only trusted root before devices have received certificates
from the next CA.

## Remaining trust boundary

mTLS proves possession of a private key for a certificate issued by an
authorized CA. It doesn't bind the certificate subject to `AzureAdDeviceId`
and doesn't make a compromised endpoint trustworthy. A holder of any eligible
certificate can submit telemetry containing a different device identifier.

For higher assurance, add a server-side Microsoft Graph/Intune lookup that
confirms the reported device exists, is enabled, and is in the intended
deployment group, or restore a certificate-subject-to-payload binding. Keep
this optional because it requires additional Graph application permissions or
a prescribed certificate subject format.

## Microsoft references

- [Create and assign SCEP certificate profiles in Intune](https://learn.microsoft.com/intune/intune-service/protect/certificates-profile-scep)
- [Configure TLS mutual authentication in Azure App Service](https://learn.microsoft.com/azure/app-service/app-service-web-configure-tls-mutual-auth)
