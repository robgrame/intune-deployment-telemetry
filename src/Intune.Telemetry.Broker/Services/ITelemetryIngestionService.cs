using Intune.Telemetry.Broker.Models;

namespace Intune.Telemetry.Broker.Services;

public interface ITelemetryIngestionService
{
    Task UploadAsync(TelemetryPayload payload, CancellationToken cancellationToken);
}
