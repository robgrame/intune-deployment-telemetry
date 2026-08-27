using System.Text.Json;
using Intune.Telemetry.Broker.Models;

namespace Intune.Telemetry.Broker.Services;

public sealed class TelemetryPayloadValidator
{
    private const int MaximumExtensionNodes = 2048;
    private const int MaximumExtensionStringLength = 4096;
    private readonly TimeProvider _timeProvider;

    public TelemetryPayloadValidator()
        : this(TimeProvider.System)
    {
    }

    public TelemetryPayloadValidator(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public PayloadValidationResult Validate(TelemetryPayload? payload)
    {
        if (payload is null)
        {
            return PayloadValidationResult.Invalid("Payload is required.");
        }

        if (!Guid.TryParse(payload.AzureAdDeviceId, out Guid deviceId) || deviceId == Guid.Empty)
        {
            return PayloadValidationResult.Invalid("AzureAdDeviceId must be a non-empty GUID.");
        }

        if (payload.TimestampUtc is null)
        {
            return PayloadValidationResult.Invalid("TimestampUtc is required.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (payload.TimestampUtc < now.AddDays(-30) || payload.TimestampUtc > now.AddMinutes(10))
        {
            return PayloadValidationResult.Invalid("TimestampUtc is outside the accepted range.");
        }

        if (!Guid.TryParse(payload.ExecutionId, out Guid executionId) || executionId == Guid.Empty)
        {
            return PayloadValidationResult.Invalid("ExecutionId must be a non-empty GUID.");
        }

        PayloadValidationResult scalarResult =
            ValidateRequiredString(payload.ScriptVersion, nameof(payload.ScriptVersion), 64)
            .Then(() => ValidateOptionalString(payload.DeviceName, nameof(payload.DeviceName), 255))
            .Then(() => ValidateOptionalString(payload.DeviceId, nameof(payload.DeviceId), 256))
            .Then(() => ValidateOptionalString(payload.ManagedDeviceId, nameof(payload.ManagedDeviceId), 256))
            .Then(() => ValidateOptionalGuid(payload.TenantDirectoryId, nameof(payload.TenantDirectoryId)))
            .Then(() => ValidateOptionalString(payload.UserUPN, nameof(payload.UserUPN), 320))
            .Then(() => ValidateOptionalString(
                payload.CurrentLoggedOnUser,
                nameof(payload.CurrentLoggedOnUser),
                320))
            .Then(() => ValidateOptionalGuid(payload.CorrelationId, nameof(payload.CorrelationId)));
        if (!scalarResult.IsValid)
        {
            return scalarResult;
        }

        if (payload.RestartPendingReasons is { Count: > 64 } ||
            payload.RestartPendingReasons?.Any(reason =>
                string.IsNullOrWhiteSpace(reason) || reason.Length > 256) == true)
        {
            return PayloadValidationResult.Invalid("RestartPendingReasons is invalid.");
        }

        PayloadValidationResult collectionResult = ValidateEvents(payload.MdmEvents)
            .Then(() => ValidateTasks(payload.MdmScheduledTasks))
            .Then(() => ValidateErrors(payload.Errors));
        if (!collectionResult.IsValid)
        {
            return collectionResult;
        }

        int extensionNodeCount = 0;
        PayloadValidationResult extensionResult = ValidateExtensions(
            payload.AdditionalData,
            ref extensionNodeCount);
        if (!extensionResult.IsValid)
        {
            return extensionResult;
        }

        foreach (MdmEvent item in payload.MdmEvents ?? [])
        {
            extensionResult = ValidateExtensions(item.AdditionalData, ref extensionNodeCount);
            if (!extensionResult.IsValid)
            {
                return extensionResult;
            }
        }

        foreach (MdmScheduledTask item in payload.MdmScheduledTasks ?? [])
        {
            extensionResult = ValidateExtensions(item.AdditionalData, ref extensionNodeCount);
            if (!extensionResult.IsValid)
            {
                return extensionResult;
            }
        }

        foreach (TelemetryError item in payload.Errors ?? [])
        {
            extensionResult = ValidateExtensions(item.AdditionalData, ref extensionNodeCount);
            if (!extensionResult.IsValid)
            {
                return extensionResult;
            }
        }

        return PayloadValidationResult.Valid(deviceId);
    }

    private static PayloadValidationResult ValidateEvents(IReadOnlyList<MdmEvent>? events)
    {
        if (events is { Count: > 500 })
        {
            return PayloadValidationResult.Invalid("MDMEvents contains too many items.");
        }

        foreach (MdmEvent item in events ?? [])
        {
            if (item.TimeCreatedUtc is null ||
                item.EventId is null or < 0 ||
                item.RecordId is < 0)
            {
                return PayloadValidationResult.Invalid("An MDMEvents item has invalid required fields.");
            }

            PayloadValidationResult result =
                ValidateOptionalString(item.Level, nameof(item.Level), 64)
                .Then(() => ValidateOptionalGuid(item.ActivityId, nameof(item.ActivityId)))
                .Then(() => ValidateOptionalString(item.Message, nameof(item.Message), 2048));
            if (!result.IsValid)
            {
                return result;
            }
        }

        return PayloadValidationResult.Valid(Guid.Empty);
    }

    private static PayloadValidationResult ValidateTasks(IReadOnlyList<MdmScheduledTask>? tasks)
    {
        if (tasks is { Count: > 256 })
        {
            return PayloadValidationResult.Invalid("MDMScheduledTasks contains too many items.");
        }

        foreach (MdmScheduledTask item in tasks ?? [])
        {
            PayloadValidationResult result =
                ValidateRequiredString(item.TaskName, nameof(item.TaskName), 256)
                .Then(() => ValidateRequiredString(item.TaskPath, nameof(item.TaskPath), 1024))
                .Then(() => ValidateRequiredString(item.State, nameof(item.State), 64));
            if (!result.IsValid)
            {
                return result;
            }
        }

        return PayloadValidationResult.Valid(Guid.Empty);
    }

    private static PayloadValidationResult ValidateErrors(IReadOnlyList<TelemetryError>? errors)
    {
        if (errors is { Count: > 25 })
        {
            return PayloadValidationResult.Invalid("Errors contains too many items.");
        }

        foreach (TelemetryError item in errors ?? [])
        {
            PayloadValidationResult result =
                ValidateRequiredString(item.Operation, nameof(item.Operation), 256)
                .Then(() => ValidateRequiredString(item.Message, nameof(item.Message), 2048))
                .Then(() => ValidateRequiredString(item.ErrorType, nameof(item.ErrorType), 512))
                .Then(() => ValidateOptionalString(item.HResult, nameof(item.HResult), 32));
            if (item.TimestampUtc is null || !result.IsValid)
            {
                return PayloadValidationResult.Invalid("An Errors item is invalid.");
            }
        }

        return PayloadValidationResult.Valid(Guid.Empty);
    }

    private static PayloadValidationResult ValidateExtensions(
        IDictionary<string, JsonElement>? extensions,
        ref int nodeCount)
    {
        if (extensions is null)
        {
            return PayloadValidationResult.Valid(Guid.Empty);
        }

        foreach ((string propertyName, JsonElement value) in extensions)
        {
            if (propertyName.Length is 0 or > 128)
            {
                return PayloadValidationResult.Invalid("An extension property name is invalid.");
            }

            PayloadValidationResult result = ValidateJsonElement(value, ref nodeCount);
            if (!result.IsValid)
            {
                return result;
            }
        }

        return PayloadValidationResult.Valid(Guid.Empty);
    }

    private static PayloadValidationResult ValidateJsonElement(JsonElement element, ref int nodeCount)
    {
        nodeCount++;
        if (nodeCount > MaximumExtensionNodes)
        {
            return PayloadValidationResult.Invalid("Extension data is too complex.");
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.String when element.GetString()?.Length > MaximumExtensionStringLength:
                return PayloadValidationResult.Invalid("An extension string is too long.");
            case JsonValueKind.Object:
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (property.Name.Length is 0 or > 128)
                    {
                        return PayloadValidationResult.Invalid("An extension property name is invalid.");
                    }

                    PayloadValidationResult childResult = ValidateJsonElement(property.Value, ref nodeCount);
                    if (!childResult.IsValid)
                    {
                        return childResult;
                    }
                }

                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in element.EnumerateArray())
                {
                    PayloadValidationResult childResult = ValidateJsonElement(item, ref nodeCount);
                    if (!childResult.IsValid)
                    {
                        return childResult;
                    }
                }

                break;
            case JsonValueKind.Undefined:
                return PayloadValidationResult.Invalid("Extension data contains an undefined value.");
        }

        return PayloadValidationResult.Valid(Guid.Empty);
    }

    private static PayloadValidationResult ValidateRequiredString(
        string? value,
        string name,
        int maximumLength) =>
        string.IsNullOrWhiteSpace(value) || value.Length > maximumLength
            ? PayloadValidationResult.Invalid($"{name} is required and must be at most {maximumLength} characters.")
            : PayloadValidationResult.Valid(Guid.Empty);

    private static PayloadValidationResult ValidateOptionalString(
        string? value,
        string name,
        int maximumLength) =>
        value is not null && (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
            ? PayloadValidationResult.Invalid($"{name} must be at most {maximumLength} characters.")
            : PayloadValidationResult.Valid(Guid.Empty);

    private static PayloadValidationResult ValidateOptionalGuid(string? value, string name) =>
        value is not null && (!Guid.TryParse(value, out Guid guid) || guid == Guid.Empty)
            ? PayloadValidationResult.Invalid($"{name} must be a non-empty GUID.")
            : PayloadValidationResult.Valid(Guid.Empty);
}

public sealed record PayloadValidationResult(bool IsValid, Guid DeviceId, string? Error)
{
    public static PayloadValidationResult Valid(Guid deviceId) => new(true, deviceId, null);

    public static PayloadValidationResult Invalid(string error) => new(false, Guid.Empty, error);

    public PayloadValidationResult Then(Func<PayloadValidationResult> next) =>
        IsValid ? next() : this;
}
