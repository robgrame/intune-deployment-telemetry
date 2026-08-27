# Security policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting in the repository **Security** tab and include:

- affected version and deployment SKU;
- reproducible steps;
- expected and observed behavior;
- impact and suggested mitigation, if known.

Do not include production certificates, workspace identifiers, device
telemetry, access tokens, or personal data.

## Security boundary

The endpoint script is untrusted input. The Azure broker independently
validates certificate validity, Client Authentication EKU, custom-root chain,
and the immediate issuing CA SHA-256 fingerprint. It also enforces payload
limits and uses managed identity for Azure Monitor ingestion.

The selected authorization model doesn't bind certificate subject to the
claimed device ID and deliberately disables CRL/OCSP validation because the
private CA publication points might not be reachable from Azure. An eligible
certificate can therefore report another device identifier, and individual
certificate revocation doesn't immediately deny access. Remove an issuing CA
fingerprint or rotate the CA to contain a certificate compromise.

No Log Analytics Shared Key ingestion mode is included.
