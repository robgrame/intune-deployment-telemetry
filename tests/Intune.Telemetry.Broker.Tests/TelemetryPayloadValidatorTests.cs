using System.Text.Json;
using Intune.Telemetry.Broker.Models;
using Intune.Telemetry.Broker.Services;

namespace Intune.Telemetry.Broker.Tests;

public sealed class TelemetryPayloadValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 27, 15, 0, 0, TimeSpan.Zero);
    private readonly TelemetryPayloadValidator _validator = new(new FixedTimeProvider(Now));

    [Fact]
    public void Validate_WithValidScriptPayloadShape_Succeeds()
    {
        Guid deviceId = Guid.NewGuid();
        TelemetryPayload payload = CreateValidPayload(deviceId);
        payload.MdmEvents =
        [
            new MdmEvent
            {
                TimeCreatedUtc = Now.AddMinutes(-1),
                EventId = 814,
                RecordId = 42,
                Level = "Information",
                ActivityId = Guid.NewGuid().ToString(),
                Message = "MDM event",
            },
        ];
        payload.MdmScheduledTasks =
        [
            new MdmScheduledTask
            {
                TaskName = "Schedule #1",
                TaskPath = "\\Microsoft\\Windows\\EnterpriseMgmt\\",
                State = "Ready",
            },
        ];
        payload.Errors =
        [
            new TelemetryError
            {
                TimestampUtc = Now,
                Operation = "Test",
                Message = "Expected error",
                ErrorType = "System.InvalidOperationException",
                HResult = "0x80131509",
            },
        ];

        PayloadValidationResult result = _validator.Validate(payload);

        Assert.True(result.IsValid);
        Assert.Equal(deviceId, result.DeviceId);
    }

    [Theory]
    [InlineData("AzureAdDeviceId")]
    [InlineData("TimestampUtc")]
    [InlineData("ExecutionId")]
    [InlineData("ScriptVersion")]
    public void Validate_WhenRequiredFieldIsMissing_Fails(string field)
    {
        TelemetryPayload payload = CreateValidPayload(Guid.NewGuid());
        switch (field)
        {
            case "AzureAdDeviceId":
                payload.AzureAdDeviceId = null;
                break;
            case "TimestampUtc":
                payload.TimestampUtc = null;
                break;
            case "ExecutionId":
                payload.ExecutionId = null;
                break;
            case "ScriptVersion":
                payload.ScriptVersion = null;
                break;
        }

        PayloadValidationResult result = _validator.Validate(payload);

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData(-31, 0)]
    [InlineData(0, 11)]
    public void Validate_WhenTimestampIsOutsideBounds_Fails(int days, int minutes)
    {
        TelemetryPayload payload = CreateValidPayload(Guid.NewGuid());
        payload.TimestampUtc = Now.AddDays(days).AddMinutes(minutes);

        PayloadValidationResult result = _validator.Validate(payload);

        Assert.False(result.IsValid);
        Assert.Contains("TimestampUtc", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WhenUnknownStringIsOversized_Fails()
    {
        TelemetryPayload payload = CreateValidPayload(Guid.NewGuid());
        using JsonDocument document = JsonDocument.Parse($"\"{new string('x', 4097)}\"");
        payload.AdditionalData = new Dictionary<string, JsonElement>
        {
            ["FutureField"] = document.RootElement.Clone(),
        };

        PayloadValidationResult result = _validator.Validate(payload);

        Assert.False(result.IsValid);
        Assert.Contains("extension string", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_WhenNestedCollectionsExceedLimits_Fails()
    {
        TelemetryPayload payload = CreateValidPayload(Guid.NewGuid());
        payload.Errors = Enumerable.Range(0, 26)
            .Select(_ => new TelemetryError
            {
                TimestampUtc = Now,
                Operation = "Operation",
                Message = "Message",
                ErrorType = "Error",
            })
            .ToArray();

        PayloadValidationResult result = _validator.Validate(payload);

        Assert.False(result.IsValid);
        Assert.Contains("too many", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ApplyServerMetadata_PreservesExtensionsAndOverwritesSpoofedServerFields()
    {
        Guid deviceId = Guid.NewGuid();
        string json = $$"""
            {
              "TimestampUtc": "{{Now:O}}",
              "AzureAdDeviceId": "{{deviceId}}",
              "ExecutionId": "{{Guid.NewGuid()}}",
              "ScriptVersion": "1.0.0",
              "FutureObject": { "value": 7 },
              "BrokerRequestId": "spoofed",
              "ClientCertificateThumbprint": "spoofed",
              "ClientCertificateIssuerThumbprint": "spoofed"
            }
            """;

        TelemetryPayload payload =
            JsonSerializer.Deserialize<TelemetryPayload>(json, TelemetryJson.Options)!;
        TelemetryPayloadEnricher.ApplyServerMetadata(
            payload,
            Now,
            "server-request-id",
            "server-thumbprint",
            "server-issuer-thumbprint");

        Assert.Equal(7, payload.AdditionalData!["FutureObject"].GetProperty("value").GetInt32());
        Assert.Equal("server-request-id", payload.BrokerRequestId);
        Assert.Equal("server-thumbprint", payload.ClientCertificateThumbprint);
        Assert.Equal("server-issuer-thumbprint", payload.ClientCertificateIssuerThumbprint);
        Assert.True(_validator.Validate(payload).IsValid);
        string serialized = JsonSerializer.Serialize(payload, TelemetryJson.Options);
        Assert.Contains("\"AzureAdDeviceId\"", serialized, StringComparison.Ordinal);
        Assert.Contains(
            "\"ClientCertificateIssuerThumbprint\":\"server-issuer-thumbprint\"",
            serialized,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Deserialize_WithExcessiveDepth_Throws()
    {
        string nested = string.Concat(Enumerable.Repeat("{\"value\":", 17)) +
                        "true" +
                        string.Concat(Enumerable.Repeat("}", 17));

        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<TelemetryPayload>(nested, TelemetryJson.Options));
    }

    private static TelemetryPayload CreateValidPayload(Guid deviceId) =>
        new()
        {
            AzureAdDeviceId = deviceId.ToString(),
            TimestampUtc = Now,
            ExecutionId = Guid.NewGuid().ToString(),
            ScriptVersion = "1.0.0",
            DeviceName = "TEST-DEVICE",
            TenantDirectoryId = Guid.NewGuid().ToString(),
            CorrelationId = Guid.NewGuid().ToString(),
        };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
