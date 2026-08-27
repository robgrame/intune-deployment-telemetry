using Azure.Core;
using Azure.Identity;
using Azure.Monitor.Ingestion;
using Intune.Telemetry.Broker.Configuration;
using Intune.Telemetry.Broker.Security;
using Intune.Telemetry.Broker.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

TokenCredential credential = AzureBootstrapConfiguration.CreateSystemAssignedCredential();

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureAppConfiguration((_, configuration) =>
    {
        IConfigurationRoot bootstrapConfiguration = configuration.Build();
        try
        {
            AzureBootstrapConfiguration.AddAzureAppConfigurationIfConfigured(
                configuration,
                bootstrapConfiguration,
                credential);
        }
        finally
        {
            (bootstrapConfiguration as IDisposable)?.Dispose();
        }
    })
    .ConfigureServices((context, services) =>
    {
        BrokerOptions options = BrokerOptions.FromConfiguration(context.Configuration);

        services.AddSingleton(options);
        services.AddSingleton<ClientCertificateValidator>();
        services.AddSingleton<TelemetryPayloadValidator>();

        services.AddSingleton(credential);
        services.AddSingleton(provider => new LogsIngestionClient(
            options.LogsIngestionEndpoint,
            provider.GetRequiredService<TokenCredential>()));
        services.AddSingleton<ITelemetryIngestionService, LogsTelemetryIngestionService>();
    })
    .Build();

await host.RunAsync();
