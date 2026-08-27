using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Intune.Telemetry.Broker.Security;

public static class CertificateFingerprint
{
    private const int Sha256HexLength = 64;

    public static string ComputeSha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }

    public static bool TryNormalizeSha256(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var builder = new StringBuilder(Sha256HexLength);
        foreach (char character in value)
        {
            if (Uri.IsHexDigit(character))
            {
                builder.Append(char.ToUpperInvariant(character));
            }
            else if (character is ':' or '-' || char.IsWhiteSpace(character))
            {
                continue;
            }
            else
            {
                return false;
            }
        }

        if (builder.Length != Sha256HexLength)
        {
            return false;
        }

        normalized = builder.ToString();
        return true;
    }
}
