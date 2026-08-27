using System.Text.Json;
using System.Text.Json.Serialization;

namespace Intune.Telemetry.Broker.Models;

public sealed class TelemetryPayload
{
    public string? AzureAdDeviceId { get; set; }

    public DateTimeOffset? TimestampUtc { get; set; }

    public string? ExecutionId { get; set; }

    public string? ScriptVersion { get; set; }

    public string? DeviceName { get; set; }

    public string? DeviceId { get; set; }

    public string? ManagedDeviceId { get; set; }

    public string? TenantDirectoryId { get; set; }

    public string? UserUPN { get; set; }

    public string? CurrentLoggedOnUser { get; set; }

    public string? CorrelationId { get; set; }

    public IReadOnlyList<string>? RestartPendingReasons { get; set; }

    [JsonPropertyName("MDMEvents")]
    public IReadOnlyList<MdmEvent>? MdmEvents { get; set; }

    [JsonPropertyName("MDMScheduledTasks")]
    public IReadOnlyList<MdmScheduledTask>? MdmScheduledTasks { get; set; }

    public IReadOnlyList<TelemetryError>? Errors { get; set; }

    public DateTimeOffset BrokerReceivedTimestampUtc { get; set; }

    public string? BrokerRequestId { get; set; }

    public string? ClientCertificateThumbprint { get; set; }

    public string? ClientCertificateIssuerThumbprint { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalData { get; set; }
}

public sealed class MdmEvent
{
    public DateTimeOffset? TimeCreatedUtc { get; set; }

    public int? EventId { get; set; }

    public string? Level { get; set; }

    public long? RecordId { get; set; }

    public string? ActivityId { get; set; }

    public string? Message { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalData { get; set; }
}

public sealed class MdmScheduledTask
{
    public string? TaskName { get; set; }

    public string? TaskPath { get; set; }

    public string? State { get; set; }

    public DateTimeOffset? LastRunTimeUtc { get; set; }

    public DateTimeOffset? NextRunTimeUtc { get; set; }

    public int? LastTaskResult { get; set; }

    public int? NumberOfMissedRuns { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalData { get; set; }
}

public sealed class TelemetryError
{
    public DateTimeOffset? TimestampUtc { get; set; }

    public string? Operation { get; set; }

    public string? Message { get; set; }

    public string? ErrorType { get; set; }

    public string? HResult { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalData { get; set; }
}
