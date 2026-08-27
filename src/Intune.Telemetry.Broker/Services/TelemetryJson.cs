using System.Text.Json;
using System.Text.Json.Serialization;

namespace Intune.Telemetry.Broker.Services;

public static class TelemetryJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNamingPolicy = null,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };
}
