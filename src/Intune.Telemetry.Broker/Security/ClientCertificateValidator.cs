using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Intune.Telemetry.Broker.Configuration;

namespace Intune.Telemetry.Broker.Security;

public sealed class ClientCertificateValidator
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private readonly BrokerOptions _options;
    private readonly TimeProvider _timeProvider;

    public ClientCertificateValidator(BrokerOptions options)
        : this(options, TimeProvider.System)
    {
    }

    public ClientCertificateValidator(BrokerOptions options, TimeProvider timeProvider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public CertificateValidationResult ValidateHeader(string? encodedCertificate)
    {
        if (string.IsNullOrWhiteSpace(encodedCertificate))
        {
            return CertificateValidationResult.Failed(CertificateValidationFailure.Missing);
        }

        X509Certificate2 certificate;
        try
        {
            byte[] der = Convert.FromBase64String(encodedCertificate);
            certificate = X509CertificateLoader.LoadCertificate(der);
        }
        catch (FormatException)
        {
            return CertificateValidationResult.Failed(CertificateValidationFailure.Malformed);
        }
        catch (CryptographicException)
        {
            return CertificateValidationResult.Failed(CertificateValidationFailure.Malformed);
        }

        string certificateFingerprint = CertificateFingerprint.ComputeSha256(certificate);
        string fingerprintSuffix = certificateFingerprint[^8..];
        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (now < certificate.NotBefore.ToUniversalTime() ||
            now >= certificate.NotAfter.ToUniversalTime())
        {
            certificate.Dispose();
            return CertificateValidationResult.Failed(
                CertificateValidationFailure.ValidityPeriod,
                fingerprintSuffix);
        }

        if (!HasClientAuthenticationEku(certificate))
        {
            certificate.Dispose();
            return CertificateValidationResult.Failed(
                CertificateValidationFailure.EnhancedKeyUsage,
                fingerprintSuffix);
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        foreach (X509Certificate2 root in _options.TrustedRoots)
        {
            chain.ChainPolicy.CustomTrustStore.Add(root);
        }

        if (!chain.Build(certificate))
        {
            certificate.Dispose();
            return CertificateValidationResult.Failed(
                CertificateValidationFailure.Untrusted,
                fingerprintSuffix);
        }

        if (chain.ChainElements.Count < 2)
        {
            certificate.Dispose();
            return CertificateValidationResult.Failed(
                CertificateValidationFailure.IssuerNotAllowed,
                fingerprintSuffix);
        }

        X509Certificate2 issuerCertificate = chain.ChainElements[1].Certificate;
        string issuerFingerprint = CertificateFingerprint.ComputeSha256(issuerCertificate);
        if (!_options.AllowedIssuerSha256Thumbprints.Contains(issuerFingerprint))
        {
            certificate.Dispose();
            return CertificateValidationResult.Failed(
                CertificateValidationFailure.IssuerNotAllowed,
                fingerprintSuffix);
        }

        return CertificateValidationResult.Succeeded(
            certificate,
            certificateFingerprint,
            issuerFingerprint,
            fingerprintSuffix);
    }

    private static bool HasClientAuthenticationEku(X509Certificate2 certificate)
    {
        X509EnhancedKeyUsageExtension? eku = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();

        return eku is not null &&
               eku.EnhancedKeyUsages
                   .Cast<Oid>()
                   .Any(oid => string.Equals(oid.Value, ClientAuthenticationOid, StringComparison.Ordinal));
    }
}

public sealed record CertificateValidationResult(
    bool IsValid,
    CertificateValidationFailure Failure,
    X509Certificate2? Certificate,
    string? Sha256Fingerprint,
    string? IssuerSha256Fingerprint,
    string? Sha256FingerprintSuffix)
{
    public static CertificateValidationResult Succeeded(
        X509Certificate2 certificate,
        string sha256Fingerprint,
        string issuerSha256Fingerprint,
        string sha256FingerprintSuffix) =>
        new(
            true,
            CertificateValidationFailure.None,
            certificate,
            sha256Fingerprint,
            issuerSha256Fingerprint,
            sha256FingerprintSuffix);

    public static CertificateValidationResult Failed(
        CertificateValidationFailure failure,
        string? sha256FingerprintSuffix = null) =>
        new(false, failure, null, null, null, sha256FingerprintSuffix);
}

public enum CertificateValidationFailure
{
    None,
    Missing,
    Malformed,
    ValidityPeriod,
    EnhancedKeyUsage,
    Untrusted,
    IssuerNotAllowed,
}
