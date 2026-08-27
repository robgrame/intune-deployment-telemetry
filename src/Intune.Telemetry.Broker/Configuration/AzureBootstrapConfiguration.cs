using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Configuration;

namespace Intune.Telemetry.Broker.Configuration;

public static class AzureBootstrapConfiguration
{
    private static readonly string[] BrokerRuntimeKeys =
    [
        "LOGS_INGESTION_ENDPOINT",
        "LOGS_DCR_IMMUTABLE_ID",
        "LOGS_STREAM_NAME",
        "CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64",
        "CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS",
        "TELEMETRY_MAX_BODY_BYTES",
    ];

    public const string EndpointKey = "AZURE_APPCONFIG_ENDPOINT";
    public const string BrokerKeyPrefix = "IntuneTelemetry:";

    public static TokenCredential CreateSystemAssignedCredential() =>
        new DefaultAzureCredential(
            new DefaultAzureCredentialOptions
            {
                ExcludeEnvironmentCredential = true,
                ExcludeWorkloadIdentityCredential = true,
                ExcludeManagedIdentityCredential = false,
                ExcludeVisualStudioCredential = true,
                ExcludeVisualStudioCodeCredential = true,
                ExcludeAzureCliCredential = true,
                ExcludeAzurePowerShellCredential = true,
                ExcludeAzureDeveloperCliCredential = true,
                ExcludeInteractiveBrowserCredential = true,
                ExcludeBrokerCredential = true,
                ManagedIdentityClientId = null,
            });

    public static bool AddAzureAppConfigurationIfConfigured(
        IConfigurationBuilder configurationBuilder,
        IConfiguration bootstrapConfiguration,
        TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);
        ArgumentNullException.ThrowIfNull(bootstrapConfiguration);
        ArgumentNullException.ThrowIfNull(credential);

        Uri? endpoint = GetEndpoint(bootstrapConfiguration);
        if (endpoint is null)
        {
            return false;
        }

        configurationBuilder.AddInMemoryCollection(
            BrokerRuntimeKeys.Select(key => new KeyValuePair<string, string?>(key, null)));
        configurationBuilder.AddAzureAppConfiguration(options =>
        {
            options.Connect(endpoint, credential)
                .Select($"{BrokerKeyPrefix}*")
                .TrimKeyPrefix(BrokerKeyPrefix)
                .ConfigureKeyVault(keyVault => keyVault.SetCredential(credential));
        });

        return true;
    }

    public static Uri? GetEndpoint(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        string? configuredEndpoint = configuration[EndpointKey]?.Trim();
        if (string.IsNullOrEmpty(configuredEndpoint))
        {
            return null;
        }

        if (!Uri.TryCreate(configuredEndpoint, UriKind.Absolute, out Uri? endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new InvalidOperationException(
                $"{EndpointKey} must be an absolute HTTPS endpoint without user information, " +
                "a query, or a fragment.");
        }

        return endpoint;
    }
}
