using System.Text.Json;
using Azure.Monitor.Ingestion;
using Intune.Telemetry.Broker.Configuration;
using Intune.Telemetry.Broker.Models;

namespace Intune.Telemetry.Broker.Services;

public sealed class LogsTelemetryIngestionService : ITelemetryIngestionService
{
    private static readonly JsonSerializerOptions SerializerOptions = TelemetryJson.Options;
    private readonly LogsIngestionClient _client;
    private readonly BrokerOptions _options;

    public LogsTelemetryIngestionService(LogsIngestionClient client, BrokerOptions options)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task UploadAsync(TelemetryPayload payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);

        BinaryData log = BinaryData.FromString(JsonSerializer.Serialize(payload, SerializerOptions));
        await _client.UploadAsync(
            _options.LogsDcrImmutableId,
            _options.LogsStreamName,
            [log],
            cancellationToken: cancellationToken);
    }
}
