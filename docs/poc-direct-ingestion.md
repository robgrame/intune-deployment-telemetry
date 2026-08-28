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
- a dedicated Microsoft Entra application with a short-lived client secret;
- **Monitoring Metrics Publisher** scoped only to the experimental DCR;
- a shared Azure Monitor Workbook for customer-facing deployment evidence;
- OAuth 2.0 client-credentials authentication from the Platform Script.

The legacy HTTP Data Collector API isn't an acceptable POC shortcut. It
requires the Log Analytics workspace shared key, gives every endpoint the same
high-impact credential, and is on the retirement path in favor of the Logs
Ingestion API.

The Bicep deployment outputs the DCR endpoint, immutable ID, and Workbook
resource ID. The App Registration itself is a Microsoft Entra tenant object
and must exist before the resource-group deployment. Pass its service
principal object ID through
`INTUNE_TELEMETRY_POC_SERVICE_PRINCIPAL_OBJECT_ID`.

## Shared client-secret model

The Platform Script contains the App Registration client secret and uses it
to perform the OAuth 2.0 client-credentials flow against Microsoft Entra. This
avoids any certificate, connector, profile, or application prerequisite on the
device and therefore doesn't distort the Intune deployment-latency
measurement.

The secret authenticates the application, not the individual device. The
device identifier remains an untrusted field in the submitted payload.

The App Registration receives only **Monitoring Metrics Publisher** on the
single POC DCR. The credential can't query the workspace or manage Azure
resources. It can submit arbitrary records accepted by that DCR, so a leaked
secret can corrupt the POC dataset until revoked or expired.

This model proves transport and schema viability, not production security:

- every device or operator holding the secret can submit records as the same
  application;
- the broker's independent certificate and payload validation is removed;
- a compromised pilot device can forge records for other device IDs;
- Azure authentication failures and token acquisition become endpoint
  concerns;
- credential rotation requires updating and re-signing the Platform Script;
- Intune administrators and anyone who can read the script can recover the
  secret.
- PowerShell Script Block Logging can record the configured script, including
  the secret, in event 4104 and forward it to security tooling.
- Intune stores Platform Script content and authorized Intune/Graph
  administrators can retrieve it.

## Token and ingestion flow

1. Read the POC client ID and secret from the signed script configuration.
2. Request a token from the tenant-specific Microsoft identity platform token
   endpoint using the Azure Monitor scope.
3. POST the bounded JSON payload to the direct DCR logs-ingestion endpoint.
4. Retry only transient responses with bounded exponential backoff.
5. Never persist the access token; keep it in memory for no longer than its
   validity period.

## Phases

1. Create a dedicated Entra application and service principal.
2. Create a client secret with an expiry no later than the POC end date.
3. Deploy the `poc` Bicep profile with the service principal object ID. The
   deployment creates Log Analytics, the table, a direct DCR, its scoped role
   assignment, and the deployment-evidence Workbook.
4. Configure the endpoint script with `UploadMode = 'DirectLogs'`, the tenant
   ID, client ID, client secret, and Bicep outputs.
5. Keep the secret in the ignored adjacent `*.secret.txt` file and use
   `New-ConfiguredPocPlatformScript.ps1` to generate the single-file script
   immediately before signing and assignment.
6. Sign and assign the generated Platform Script to the disposable POC device
   group.
7. Measure accepted rows, latency, failures, and operational effort.
8. Delete the client secret and direct-ingestion resource group when the
   experiment ends.

In the manual POC workflow, `AssignmentToExecutionMinutes` is
generation-to-execution time and includes signing, upload, and assignment
delay. Run the generator immediately before those actions and record the UTC
timestamp it prints. Exact assignment-to-execution measurement requires
automating generation, Graph upload, and assignment in one operation.

## Guardrails

- Never use a Log Analytics workspace shared key.
- Create a secret only for this POC application and DCR.
- Set secret expiry to no more than 45 days and no later than the experiment
  end date.
- Use a separate tenant application and DCR for the experiment.
- Keep the pilot to a maximum of five disposable test devices without
  sensitive user data.
- Keep `DirectIncludeSensitiveData = $false`, which excludes `UserUPN`,
  `CurrentLoggedOnUser`, and raw event messages. Enable it only after an
  explicit privacy review.
- Apply a 30-day retention and a 1-GB/day workspace cap.
- Set an explicit end date no later than 30 days after deployment.
- Delete the client secret from the App Registration at experiment end.
- Delete local `*.secret.txt` and `*.generated.ps1` files at experiment end.
- Never commit a configured script containing the secret.
- Assume the secret is disclosed to every system that retains PowerShell
  script-block logs or Intune script content. Keep DCR-only RBAC and mandatory
  expiry/revocation as the containment boundary.
- The script's own transcript records runtime output, not the configuration
  block or secret.
- Monitor authentication failures, DCR errors, throttling, and missing data.
- Treat all endpoint-supplied identifiers as untrusted.

## Exit criteria

Direct ingestion is successful only if it demonstrates the required latency
and reliability without using a workspace key. Production adoption requires a
formal exception accepting an embedded shared client secret, application-level
rather than device-level identity, and the loss of broker-side validation.
Otherwise, move to `dev` or `prod`, which restore the broker security boundary.
