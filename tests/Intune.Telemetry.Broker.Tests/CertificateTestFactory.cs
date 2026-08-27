using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Intune.Telemetry.Broker.Tests;

internal static class CertificateTestFactory
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    public static CertificateChain Create(
        string commonName = "arbitrary-client",
        DateTimeOffset? leafNotBefore = null,
        DateTimeOffset? leafNotAfter = null,
        bool includeClientAuthenticationEku = true)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=Telemetry Test Root",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));

        X509Certificate2 rootWithKey =
            rootRequest.CreateSelfSigned(now.AddYears(-2), now.AddYears(2));
        X509Certificate2 root = X509CertificateLoader.LoadCertificate(
            rootWithKey.Export(X509ContentType.Cert));

        using RSA leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            $"CN={commonName}",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (includeClientAuthenticationEku)
        {
            var usages = new OidCollection
            {
                new Oid(ClientAuthenticationOid),
            };
            leafRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(usages, true));
        }

        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        X509Certificate2 leaf = leafRequest.Create(
            rootWithKey,
            leafNotBefore ?? now.AddDays(-1),
            leafNotAfter ?? now.AddDays(30),
            serialNumber);
        rootWithKey.Dispose();

        return new CertificateChain(root, leaf);
    }

    internal sealed class CertificateChain(
        X509Certificate2 root,
        X509Certificate2 leaf) : IDisposable
    {
        public X509Certificate2 Root { get; } = root;

        public X509Certificate2 Leaf { get; } = leaf;

        public string EncodedLeaf =>
            Convert.ToBase64String(Leaf.Export(X509ContentType.Cert));

        public void Dispose()
        {
            Root.Dispose();
            Leaf.Dispose();
        }
    }
}
