using Intune.Telemetry.Broker.Configuration;
using Intune.Telemetry.Broker.Security;

namespace Intune.Telemetry.Broker.Tests;

public sealed class ClientCertificateValidatorTests
{
    [Fact]
    public void ValidateHeader_WithAllowedIssuerFingerprint_Succeeds()
    {
        using CertificateTestFactory.CertificateChain chain =
            CertificateTestFactory.Create("CN-is-not-a-device-id");
        using BrokerOptions options = CreateOptions(chain);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(chain.EncodedLeaf);

        Assert.True(result.IsValid);
        Assert.Equal(CertificateValidationFailure.None, result.Failure);
        Assert.NotNull(result.Certificate);
        Assert.Equal(CertificateFingerprint.ComputeSha256(chain.Leaf), result.Sha256Fingerprint);
        Assert.Equal(
            CertificateFingerprint.ComputeSha256(chain.Root),
            result.IssuerSha256Fingerprint);
        Assert.EndsWith(result.Sha256FingerprintSuffix!, result.Sha256Fingerprint);
        result.Certificate.Dispose();
    }

    [Theory]
    [InlineData(null, CertificateValidationFailure.Missing)]
    [InlineData("", CertificateValidationFailure.Missing)]
    [InlineData("not-base64", CertificateValidationFailure.Malformed)]
    [InlineData("bm90LWEta2V5", CertificateValidationFailure.Malformed)]
    public void ValidateHeader_WithMissingOrMalformedValue_Fails(
        string? header,
        CertificateValidationFailure expectedFailure)
    {
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create();
        using BrokerOptions options = CreateOptions(chain);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(header);

        Assert.False(result.IsValid);
        Assert.Equal(expectedFailure, result.Failure);
        Assert.Null(result.Certificate);
    }

    [Fact]
    public void ValidateHeader_WithUntrustedChain_Fails()
    {
        using CertificateTestFactory.CertificateChain trustedChain = CertificateTestFactory.Create();
        using CertificateTestFactory.CertificateChain untrustedChain = CertificateTestFactory.Create();
        using BrokerOptions options = CreateOptions(trustedChain);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(untrustedChain.EncodedLeaf);

        Assert.False(result.IsValid);
        Assert.Equal(CertificateValidationFailure.Untrusted, result.Failure);
    }

    [Fact]
    public void ValidateHeader_WithTrustedButWrongIssuerFingerprint_Fails()
    {
        using CertificateTestFactory.CertificateChain actualIssuer = CertificateTestFactory.Create();
        using CertificateTestFactory.CertificateChain allowedIssuer = CertificateTestFactory.Create();
        using BrokerOptions options = BrokerOptions.CreateForTests(
            [actualIssuer.Root, allowedIssuer.Root],
            [CertificateFingerprint.ComputeSha256(allowedIssuer.Root)]);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(actualIssuer.EncodedLeaf);

        Assert.False(result.IsValid);
        Assert.Equal(CertificateValidationFailure.IssuerNotAllowed, result.Failure);
    }

    [Fact]
    public void ValidateHeader_WhenLeafFingerprintIsAllowedInsteadOfIssuer_Fails()
    {
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create();
        using BrokerOptions options = BrokerOptions.CreateForTests(
            [chain.Root],
            [CertificateFingerprint.ComputeSha256(chain.Leaf)]);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(chain.EncodedLeaf);

        Assert.False(result.IsValid);
        Assert.Equal(CertificateValidationFailure.IssuerNotAllowed, result.Failure);
    }

    [Fact]
    public void ValidateHeader_WithMultipleAllowedIssuers_AcceptsEachIssuer()
    {
        using CertificateTestFactory.CertificateChain first = CertificateTestFactory.Create();
        using CertificateTestFactory.CertificateChain second = CertificateTestFactory.Create();
        using BrokerOptions options = BrokerOptions.CreateForTests(
            [first.Root, second.Root],
            [
                CertificateFingerprint.ComputeSha256(first.Root),
                CertificateFingerprint.ComputeSha256(second.Root),
            ]);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult firstResult = validator.ValidateHeader(first.EncodedLeaf);
        CertificateValidationResult secondResult = validator.ValidateHeader(second.EncodedLeaf);

        Assert.True(firstResult.IsValid);
        Assert.True(secondResult.IsValid);
        firstResult.Certificate!.Dispose();
        secondResult.Certificate!.Dispose();
    }

    [Fact]
    public void ValidateHeader_WithoutClientAuthenticationEku_Fails()
    {
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create(
            includeClientAuthenticationEku: false);
        using BrokerOptions options = CreateOptions(chain);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(chain.EncodedLeaf);

        Assert.False(result.IsValid);
        Assert.Equal(CertificateValidationFailure.EnhancedKeyUsage, result.Failure);
    }

    [Fact]
    public void ValidateHeader_WithExpiredCertificate_Fails()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using CertificateTestFactory.CertificateChain chain = CertificateTestFactory.Create(
            leafNotBefore: now.AddDays(-10),
            leafNotAfter: now.AddDays(-1));
        using BrokerOptions options = CreateOptions(chain);
        var validator = new ClientCertificateValidator(options);

        CertificateValidationResult result = validator.ValidateHeader(chain.EncodedLeaf);

        Assert.False(result.IsValid);
        Assert.Equal(CertificateValidationFailure.ValidityPeriod, result.Failure);
    }

    private static BrokerOptions CreateOptions(
        CertificateTestFactory.CertificateChain chain) =>
        BrokerOptions.CreateForTests(
            [chain.Root],
            [CertificateFingerprint.ComputeSha256(chain.Root)]);
}
