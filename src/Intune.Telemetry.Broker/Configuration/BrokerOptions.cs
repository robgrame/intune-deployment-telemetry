using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Intune.Telemetry.Broker.Security;
using Microsoft.Extensions.Configuration;

namespace Intune.Telemetry.Broker.Configuration;

public sealed class BrokerOptions : IDisposable
{
    public const int DefaultMaxBodyBytes = 128 * 1024;

    private BrokerOptions(
        Uri logsIngestionEndpoint,
        string logsDcrImmutableId,
        string logsStreamName,
        IReadOnlyList<X509Certificate2> trustedRoots,
        IReadOnlySet<string> allowedIssuerSha256Thumbprints,
        int maxBodyBytes)
    {
        LogsIngestionEndpoint = logsIngestionEndpoint;
        LogsDcrImmutableId = logsDcrImmutableId;
        LogsStreamName = logsStreamName;
        TrustedRoots = trustedRoots;
        AllowedIssuerSha256Thumbprints = allowedIssuerSha256Thumbprints;
        MaxBodyBytes = maxBodyBytes;
    }

    public Uri LogsIngestionEndpoint { get; }

    public string LogsDcrImmutableId { get; }

    public string LogsStreamName { get; }

    public IReadOnlyList<X509Certificate2> TrustedRoots { get; }

    public IReadOnlySet<string> AllowedIssuerSha256Thumbprints { get; }

    public int MaxBodyBytes { get; }

    public static BrokerOptions FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Uri endpoint = GetHttpsUri(configuration, "LOGS_INGESTION_ENDPOINT");
        string dcrId = GetRequired(configuration, "LOGS_DCR_IMMUTABLE_ID", 256);
        string streamName = GetRequired(configuration, "LOGS_STREAM_NAME", 256);
        IReadOnlySet<string> allowedIssuers = ParseIssuerThumbprints(
            GetRequired(configuration, "CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS", 100_000));

        int maxBodyBytes = GetBoundedInt(
            configuration,
            "TELEMETRY_MAX_BODY_BYTES",
            DefaultMaxBodyBytes,
            minimum: 1024,
            maximum: 1024 * 1024);
        IReadOnlyList<X509Certificate2> roots = LoadTrustedRoots(
            GetRequired(configuration, "CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64", 1_000_000));

        return new BrokerOptions(
            endpoint,
            dcrId,
            streamName,
            roots,
            allowedIssuers,
            maxBodyBytes);
    }

    public static BrokerOptions CreateForTests(
        IEnumerable<X509Certificate2> trustedRoots,
        IEnumerable<string> allowedIssuerSha256Thumbprints,
        int maxBodyBytes = DefaultMaxBodyBytes)
    {
        ArgumentNullException.ThrowIfNull(trustedRoots);
        ArgumentNullException.ThrowIfNull(allowedIssuerSha256Thumbprints);

        return new BrokerOptions(
            new Uri("https://example.ingest.monitor.azure.com", UriKind.Absolute),
            "dcr-test",
            "Custom-Test_CL",
            trustedRoots.ToArray(),
            ParseIssuerThumbprints(string.Join(';', allowedIssuerSha256Thumbprints)),
            maxBodyBytes);
    }

    public void Dispose() => DisposeAll(TrustedRoots);

    private static string GetRequired(IConfiguration configuration, string key, int maximumLength)
    {
        string? value = configuration[key]?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > maximumLength)
        {
            throw new InvalidOperationException($"{key} is required and must be at most {maximumLength} characters.");
        }

        return value;
    }

    private static Uri GetHttpsUri(IConfiguration configuration, string key)
    {
        string value = GetRequired(configuration, key, 2048);
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidOperationException($"{key} must be an absolute HTTPS URI without user information.");
        }

        return uri;
    }

    private static int GetBoundedInt(
        IConfiguration configuration,
        string key,
        int defaultValue,
        int minimum,
        int maximum)
    {
        string? value = configuration[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int result) ||
            result < minimum ||
            result > maximum)
        {
            throw new InvalidOperationException($"{key} must be between {minimum} and {maximum}.");
        }

        return result;
    }

    private static List<X509Certificate2> LoadTrustedRoots(string encodedRoots)
    {
        var roots = new List<X509Certificate2>();
        try
        {
            foreach (string encodedRoot in encodedRoots.Split(
                         ';',
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                byte[] der = Convert.FromBase64String(encodedRoot);
                X509Certificate2 root = X509CertificateLoader.LoadCertificate(der);
                if (!IsCertificateAuthority(root))
                {
                    root.Dispose();
                    throw new InvalidOperationException(
                        "Every CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64 entry must be a CA certificate.");
                }

                roots.Add(root);
            }
        }
        catch (FormatException exception)
        {
            DisposeAll(roots);
            throw new InvalidOperationException(
                "CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64 contains invalid Base64.", exception);
        }
        catch (CryptographicException exception)
        {
            DisposeAll(roots);
            throw new InvalidOperationException(
                "CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64 contains an invalid DER certificate.", exception);
        }
        catch (InvalidOperationException)
        {
            DisposeAll(roots);
            throw;
        }

        if (roots.Count == 0)
        {
            throw new InvalidOperationException(
                "CLIENT_CERTIFICATE_TRUSTED_ROOTS_BASE64 must contain at least one certificate.");
        }

        return roots;
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority);

    private static HashSet<string> ParseIssuerThumbprints(string configuredThumbprints)
    {
        var thumbprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (string configuredThumbprint in configuredThumbprints.Split(
                     ';',
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!CertificateFingerprint.TryNormalizeSha256(
                    configuredThumbprint,
                    out string normalizedThumbprint))
            {
                throw new InvalidOperationException(
                    "CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS must contain " +
                    "semicolon-separated SHA-256 certificate thumbprints.");
            }

            thumbprints.Add(normalizedThumbprint);
        }

        if (thumbprints.Count == 0)
        {
            throw new InvalidOperationException(
                "CLIENT_CERTIFICATE_ISSUER_SHA256_THUMBPRINTS must contain at least one thumbprint.");
        }

        return thumbprints;
    }

    private static void DisposeAll(IEnumerable<X509Certificate2> certificates)
    {
        foreach (X509Certificate2 certificate in certificates)
        {
            certificate.Dispose();
        }
    }
}
