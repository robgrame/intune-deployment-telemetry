# Proof of Concept direct-ingestion plan

## Decision

The `poc` profile is a short-lived direct-ingestion experiment. Unlike `dev`,
`prod`, and `premium`, it doesn't deploy a broker.

## Supported Azure path

Use the Azure Monitor Logs Ingestion API with:

- one Log Analytics workspace and custom table;
- a direct Data Collection Rule;
- the DCR logs-ingestion endpoint, avoiding a separate DCE when private link
  isn't required;
- a dedicated Microsoft Entra application with a certificate credential;
- **Monitoring Metrics Publisher** scoped only to the experimental DCR;
- certificate-based client credentials, not a client secret or workspace key.

The legacy HTTP Data Collector API isn't an acceptable POC shortcut. It
requires the Log Analytics workspace shared key, gives every endpoint the same
high-impact credential, and is on the retirement path in favor of the Logs
Ingestion API.

The Bicep deployment outputs the DCR endpoint and immutable ID. The App
Registration itself is a Microsoft Entra tenant object and must exist before
the resource-group deployment. Pass its service principal object ID through
`INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID`.

## Shared application-certificate model

For the direct-ingestion experiment, create one separate application
certificate, register its public key on the dedicated Entra application, and
manually provision the same private key and certificate on the pilot devices.
The endpoint script uses that certificate to perform the OAuth 2.0
client-credentials flow against Microsoft Entra and then calls the DCR
logs-ingestion endpoint with the resulting bearer token.

This certificate is common to the pilot clients. It authenticates the
application, not the individual device. The device identifier remains an
untrusted field in the submitted payload.

The shared certificate is operationally preferable to embedding a client
secret or Log Analytics workspace key because the installed key can be marked
non-exportable, it has a defined expiry, and its public key is the only
credential material stored in the App Registration. It is nevertheless a
shared credential: compromise of one endpoint permits use of the application
identity until the certificate is removed or expires.

Creating identical private keys on multiple machines requires transporting an
exportable PFX at provisioning time. The PFX and its password are shared
secrets even if the installed key is subsequently marked non-exportable.
For the maximum five-device experiment, provision each disposable test device
manually from a controlled administrator workstation and securely delete the
temporary PFX afterward. Do not embed the PFX or password in an Intune script,
Win32 package, repository, or configuration profile.

This model proves transport and schema viability, not production security:

- every device holding the shared private key can submit records as the same
  application;
- the broker's independent certificate and payload validation is removed;
- a compromised pilot device can forge records for other device IDs;
- Azure authentication failures and token acquisition become endpoint
  concerns;
- credential rotation requires coordinated Entra and Intune changes.
- the provisioning PFX and password can be copied while they exist.

Do not reuse the telemetry mTLS certificate or its issuing CA for this purpose.
Keep the application credential separate so that rotation and cleanup don't
affect the device trust profile.

## Token and ingestion flow

1. Locate the shared application certificate by SHA-256 fingerprint in
   `LocalMachine\My`.
2. Build and sign a short-lived client assertion for the dedicated App
   Registration.
3. Request a token from the tenant-specific Microsoft identity platform token
   endpoint using the Azure Monitor scope.
4. POST the bounded JSON payload to the direct DCR logs-ingestion endpoint.
5. Retry only transient responses with bounded exponential backoff.
6. Never persist the access token; keep it in memory for no longer than its
   validity period.

## Phases

1. Create a dedicated Entra application and service principal.
2. Create the application certificate, register its public key on the App
   Registration, and record its SHA-256 fingerprint.
3. Deploy the `poc` Bicep profile with the service principal object ID. The
   deployment creates Log Analytics, the table, a direct DCR, and its scoped
   role assignment.
4. Configure the endpoint script with `UploadMode = 'DirectLogs'`, the tenant
   and client IDs, Bicep outputs, and certificate fingerprint.
5. Manually provision the shared certificate on a maximum of five disposable
   test devices, mark the installed private key non-exportable, and pilot
   direct ingestion.
6. Measure accepted rows, latency, failures, and operational effort.
7. Remove the Entra credential and direct-ingestion resource group when the
   experiment ends.

## Guardrails

- Never place a workspace shared key or client secret in the script.
- Use a certificate created only for this experiment, with a validity of no
  more than 45 days.
- Deploy its private key as non-exportable when the certificate-delivery
  mechanism supports it.
- Use a separate tenant application and DCR for the experiment.
- Keep the pilot to a maximum of five disposable test devices without
  sensitive user data.
- Keep `DirectIncludeSensitiveData = $false`, which excludes `UserUPN`,
  `CurrentLoggedOnUser`, and raw event messages. Enable it only after an
  explicit privacy review.
- Apply a 30-day retention and a 1-GB/day workspace cap.
- Set an explicit end date no later than 30 days after deployment.
- Remove the certificate credential from the App Registration at experiment
  end; deleting only the local certificates isn't sufficient.
- Monitor authentication failures, DCR errors, throttling, and missing data.
- Treat all endpoint-supplied identifiers as untrusted.

## Exit criteria

Direct ingestion is successful only if it demonstrates the required latency
and reliability without distributing a client secret or workspace key.
Production adoption requires a formal exception accepting a shared
endpoint-held application certificate, application-level rather than
device-level identity, and the loss of broker-side validation. Otherwise, move to `dev` or `prod`, which restore the broker security boundary.
