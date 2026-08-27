using System.Security.Cryptography.X509Certificates;
using Intune.Telemetry.Broker.Configuration;
using Intune.Telemetry.Broker.Security;
using Microsoft.Extensions.Configuration;

namespace Intune.Telemetry.Broker.Tests;

public sealed class BrokerOptionsTests
{
    [Fact]
    public void FromConfigurationDefaultsToExpectedBodyLimit()
    {
        using CertificateTestFactory.CertificateChain chain =
            CertificateTestFactory.Create(Guid.NewGuid().ToString());
        IConfiguration configuration = CreateConfiguration(
            Convert.ToBase64String(chain.Root.Export(X509ContentType.Cert)),
            CertificateFingerprint.ComputeSha256(chain.Root));

        using BrokerOptions options = BrokerOptions.FromConfiguration(configuration);

        Assert.Equal(BrokerOptions.DefaultMaxBodyBytes, options.MaxBodyBytes);
        Assert.Single(options.TrustedRoots);
    }

    [Fact]
    public void FromConfigurationAcceptsSemicolonSeparatedRoots()
    {
        using CertificateTestFactory.CertificateChain first =
            CertificateTestFactory.Create(Guid.NewGuid().ToString());
        using CertificateTestFactory.CertificateChain second =
            CertificateTestFactory.Create(Guid.NewGuid().ToString());
        string roots = string.Join(
            ';',
            Convert.ToBase64String(first.Root.Export(X509ContentType.Cert)),
            Convert.ToBase64String(second.Root.Export(X509ContentType.Cert)));
        IConfiguration configuration = CreateConfiguration(
            roots,
            CertificateFingerprint.ComputeSha256(first.Root));

        using BrokerOptions options = BrokerOptions.FromConfiguration(configuration);

        Assert.Equal(2, options.TrustedRoots.Count);
    }

    [Fact]
    public void FromConfiguration_NormalizesIssuerSha256Thumbprints()
    {
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create();
        string fingerprint = CertificateFingerprint.ComputeSha256(chain.Root);
        string delimitedLowercase = string.Join(
            ':',
            Enumerable.Range(0, fingerprint.Length / 2)
                .Select(index => fingerprint.Substring(index * 2, 2).ToLowerInvariant()));
        IConfiguration configuration = CreateConfiguration(
            Convert.ToBase64String(chain.Root.Export(X509ContentType.Cert)),
            $"  {delimitedLowercase}  ");

        using BrokerOptions options = BrokerOptions.FromConfiguration(configuration);

        Assert.Contains(fingerprint, options.AllowedIssuerSha256Thumbprints);
    }

    [Fact]
    public void FromConfiguration_AcceptsMultipleIssuerSha256Thumbprints()
    {
        using CertificateTestFactory.CertificateChain first = CertificateTestFactory.Create();
        using CertificateTestFactory.CertificateChain second = CertificateTestFactory.Create();
        string roots = string.Join(
            ';',
            Convert.ToBase64String(first.Root.Export(X509ContentType.Cert)),
            Convert.ToBase64String(second.Root.Export(X509ContentType.Cert)));
        IConfiguration configuration = CreateConfiguration(
            roots,
            string.Join(
                ';',
                CertificateFingerprint.ComputeSha256(first.Root),
                CertificateFingerprint.ComputeSha256(second.Root)));

        using BrokerOptions options = BrokerOptions.FromConfiguration(configuration);

        Assert.Equal(2, options.AllowedIssuerSha256Thumbprints.Count);
    }

    [Theory]
    [InlineData("ABC123")]
    [InlineData("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    public void FromConfiguration_RejectsInvalidIssuerSha256Thumbprints(string thumbprints)
    {
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create();
        IConfiguration configuration = CreateConfiguration(
            Convert.ToBase64String(chain.Root.Export(X509ContentType.Cert)),
            thumbprints);

        Assert.Throws<InvalidOperationException>(
            () => BrokerOptions.FromConfiguration(configuration));
    }

    [Theory]
    [InlineData("invalid-base64")]
    [InlineData("bm90LWEtY2VydGlmaWNhdGU=")]
    public void FromConfigurationRejectsMalformedRoot(string encodedRoot)
    {
        IConfiguration configuration = CreateConfiguration(encodedRoot, new string('A', 64));

        Assert.Throws<InvalidOperationException>(
            () => BrokerOptions.FromConfiguration(configuration));
    }

    private static IConfiguration CreateConfiguration(string roots, string issuerThumbprints) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["LOGS_INGESTION_ENDPOINT"] =
                    "https://example.westeurope-1.ingest.monitor.azure.com",
                ["LOGS_DCR_IMMUTABLE_ID"] = "dcr-test",
                ["LOGS_STREAM_NAME"] = "Custom-Test_CL",
                ["CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64"] = roots,
                ["CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS"] = issuerThumbprints,
            })
            .Build();
}
