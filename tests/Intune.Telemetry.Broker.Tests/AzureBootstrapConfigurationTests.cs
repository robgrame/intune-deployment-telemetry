using Azure.Core;
using Intune.Telemetry.Broker.Configuration;
using Microsoft.Extensions.Configuration;

namespace Intune.Telemetry.Broker.Tests;

public sealed class AzureBootstrapConfigurationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetEndpoint_WhenBootstrapEndpointIsAbsent_UsesLocalFallback(string? value)
    {
        IConfiguration configuration = CreateConfiguration(value);

        Uri? endpoint = AzureBootstrapConfiguration.GetEndpoint(configuration);

        Assert.Null(endpoint);
    }

    [Fact]
    public void GetEndpoint_WithValidHttpsEndpoint_ReturnsNormalizedUri()
    {
        IConfiguration configuration = CreateConfiguration(
            "  https://broker-config.azconfig.io  ");

        Uri? endpoint = AzureBootstrapConfiguration.GetEndpoint(configuration);

        Assert.Equal(new Uri("https://broker-config.azconfig.io"), endpoint);
    }

    [Theory]
    [InlineData("http://broker-config.azconfig.io")]
    [InlineData("https://user@broker-config.azconfig.io")]
    [InlineData("https://broker-config.azconfig.io?secret=value")]
    [InlineData("not-a-uri")]
    public void GetEndpoint_WithInvalidEndpoint_Throws(string value)
    {
        IConfiguration configuration = CreateConfiguration(value);

        Assert.Throws<InvalidOperationException>(
            () => AzureBootstrapConfiguration.GetEndpoint(configuration));
    }

    [Fact]
    public void BrokerKeyPrefix_IsExplicitAndMapsToExistingOptionNames()
    {
        const string appConfigurationKey =
            $"{AzureBootstrapConfiguration.BrokerKeyPrefix}LOGS_STREAM_NAME";
        const string trustedRootsKey =
            $"{AzureBootstrapConfiguration.BrokerKeyPrefix}CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64";

        string optionName = appConfigurationKey[AzureBootstrapConfiguration.BrokerKeyPrefix.Length..];

        Assert.Equal("IntuneTelemetry:", AzureBootstrapConfiguration.BrokerKeyPrefix);
        Assert.Equal("LOGS_STREAM_NAME", optionName);
        Assert.Equal(
            "IntuneTelemetry:CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64",
            trustedRootsKey);
    }

    [Fact]
    public void AddAzureAppConfigurationIfConfigured_WhenEndpointIsAbsent_PreservesLocalValues()
    {
        var builder = new ConfigurationBuilder();
        builder.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["LOGS_STREAM_NAME"] = "Custom-LocalTelemetry",
        });
        IConfigurationRoot bootstrap = builder.Build();

        bool added = AzureBootstrapConfiguration.AddAzureAppConfigurationIfConfigured(
            builder,
            bootstrap,
            new UnusedCredential());
        IConfigurationRoot configuration = builder.Build();

        Assert.False(added);
        Assert.Equal("Custom-LocalTelemetry", configuration["LOGS_STREAM_NAME"]);
        (bootstrap as IDisposable)?.Dispose();
        (configuration as IDisposable)?.Dispose();
    }

    private static IConfiguration CreateConfiguration(string? endpoint) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [AzureBootstrapConfiguration.EndpointKey] = endpoint,
            })
            .Build();

    private sealed class UnusedCredential : TokenCredential
    {
        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The credential must not be used without an endpoint.");

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<AccessToken>(
                new InvalidOperationException("The credential must not be used without an endpoint."));
    }
}
