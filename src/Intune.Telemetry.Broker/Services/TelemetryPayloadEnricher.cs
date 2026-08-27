using Intune.Telemetry.Broker.Models;

namespace Intune.Telemetry.Broker.Services;

public static class TelemetryPayloadEnricher
{
    public static void ApplyServerMetadata(
        TelemetryPayload payload,
        DateTimeOffset receivedTimestampUtc,
        string requestId,
        string clientCertificateSha256Fingerprint,
        string clientCertificateIssuerSha256Fingerprint)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientCertificateSha256Fingerprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientCertificateIssuerSha256Fingerprint);

        payload.BrokerReceivedTimestampUtc = receivedTimestampUtc;
        payload.BrokerRequestId = requestId;
        payload.ClientCertificateThumbprint = clientCertificateSha256Fingerprint;
        payload.ClientCertificateIssuerThumbprint = clientCertificateIssuerSha256Fingerprint;
    }
}
