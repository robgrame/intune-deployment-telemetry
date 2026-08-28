# Contributing

Thank you for helping improve Intune Deployment Telemetry.

## Development requirements

- .NET SDK 10
- Azure Functions Core Tools 4
- Azure CLI with Bicep
- Windows PowerShell 5.1 for endpoint-script compatibility tests

## Workflow

1. Create a branch from `main`.
2. Keep changes focused and free of tenant-specific data, except for the
   explicitly time-boxed POC identifiers described below.
3. Increment the endpoint script `Major.Minor.Build` value when changing it.
4. Run:

   ```powershell
   dotnet restore .\IntuneDeploymentTelemetry.slnx
   dotnet build .\IntuneDeploymentTelemetry.slnx --configuration Release --no-restore
   dotnet test .\IntuneDeploymentTelemetry.slnx --configuration Release --no-build
   az bicep build --file .\infra\main.bicep
   az bicep build --file .\infra\poc.bicep
   pwsh -NoProfile -File .\tests\powershell\Test-DirectIngestionPayload.ps1
   pwsh -NoProfile -File .\tests\powershell\Test-TrackedScriptPlaceholders.ps1
   powershell.exe -NoProfile -File .\tests\powershell\Test-PocScriptTemplate.ps1
   ```

5. Explain security and operational impact in the pull request.

Never commit secrets, private keys, certificates, workspace keys, device data,
or generated `local.settings.json` files.

The versioned POC Platform Script is an explicit exception for non-secret,
time-boxed identifiers: its tenant ID, App Registration client ID, DCR
endpoint, and immutable DCR ID may be committed while the POC is active.
Remove or replace them when the POC is retired. Client secrets remain
prohibited.
