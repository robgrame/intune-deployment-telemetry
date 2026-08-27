using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Azure;
using Azure.Identity;
using Intune.Telemetry.Broker.Configuration;
using Intune.Telemetry.Broker.Models;
using Intune.Telemetry.Broker.Security;
using Intune.Telemetry.Broker.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace Intune.Telemetry.Broker.Functions;

public sealed class TelemetryFunction
{
    private const string ClientCertificateHeader = "X-ARR-ClientCert";
    private readonly BrokerOptions _options;
    private readonly ClientCertificateValidator _certificateValidator;
    private readonly TelemetryPayloadValidator _payloadValidator;
    private readonly ITelemetryIngestionService _ingestionService;
    private readonly ILogger<TelemetryFunction> _logger;
    private readonly TimeProvider _timeProvider;

    public TelemetryFunction(
        BrokerOptions options,
        ClientCertificateValidator certificateValidator,
        TelemetryPayloadValidator payloadValidator,
        ITelemetryIngestionService ingestionService,
        ILogger<TelemetryFunction> logger)
        : this(
            options,
            certificateValidator,
            payloadValidator,
            ingestionService,
            logger,
            TimeProvider.System)
    {
    }

    public TelemetryFunction(
        BrokerOptions options,
        ClientCertificateValidator certificateValidator,
        TelemetryPayloadValidator payloadValidator,
        ITelemetryIngestionService ingestionService,
        ILogger<TelemetryFunction> logger,
        TimeProvider timeProvider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _certificateValidator = certificateValidator ??
            throw new ArgumentNullException(nameof(certificateValidator));
        _payloadValidator = payloadValidator ?? throw new ArgumentNullException(nameof(payloadValidator));
        _ingestionService = ingestionService ?? throw new ArgumentNullException(nameof(ingestionService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    [Function("PostTelemetry")]
    public async Task<HttpResponseData> RunAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "telemetry")] HttpRequestData request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var stopwatch = Stopwatch.StartNew();
        string requestId = Guid.NewGuid().ToString();
        string? deviceIdForLog = null;
        string? certificateSuffix = null;
        string result = "Unhandled";
        X509Certificate2? certificate = null;

        try
        {
            if (!TryGetSingleHeader(request, ClientCertificateHeader, out string? encodedCertificate))
            {
                result = "CertificateMissing";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.Unauthorized,
                    "A valid client certificate is required.",
                    requestId,
                    cancellationToken);
            }

            CertificateValidationResult certificateResult =
                _certificateValidator.ValidateHeader(encodedCertificate);
            certificateSuffix = certificateResult.Sha256FingerprintSuffix;
            if (!certificateResult.IsValid)
            {
                result = $"Certificate{certificateResult.Failure}";
                return await CreateErrorResponseAsync(
                    request,
                    certificateResult.Failure is CertificateValidationFailure.Missing or
                        CertificateValidationFailure.Malformed
                        ? HttpStatusCode.Unauthorized
                        : HttpStatusCode.Forbidden,
                    "A valid client certificate is required.",
                    requestId,
                    cancellationToken);
            }

            certificate = certificateResult.Certificate ??
                throw new InvalidOperationException("A valid certificate result must include a certificate.");

            if (!HasJsonContentType(request))
            {
                result = "UnsupportedMediaType";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.UnsupportedMediaType,
                    "Content-Type must be application/json.",
                    requestId,
                    cancellationToken);
            }

            if (HasOversizedContentLength(request, _options.MaxBodyBytes))
            {
                result = "PayloadTooLarge";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.RequestEntityTooLarge,
                    "The request body is too large.",
                    requestId,
                    cancellationToken);
            }

            byte[] body;
            try
            {
                body = await ReadBoundedBodyAsync(
                    request.Body,
                    _options.MaxBodyBytes,
                    cancellationToken);
            }
            catch (PayloadTooLargeException)
            {
                result = "PayloadTooLarge";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.RequestEntityTooLarge,
                    "The request body is too large.",
                    requestId,
                    cancellationToken);
            }

            TelemetryPayload? payload;
            try
            {
                payload = JsonSerializer.Deserialize<TelemetryPayload>(body, TelemetryJson.Options);
            }
            catch (JsonException)
            {
                result = "InvalidJson";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.BadRequest,
                    "The request body is not valid telemetry JSON.",
                    requestId,
                    cancellationToken);
            }

            PayloadValidationResult payloadResult = _payloadValidator.Validate(payload);
            if (!payloadResult.IsValid)
            {
                result = "InvalidPayload";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.BadRequest,
                    payloadResult.Error ?? "The telemetry payload is invalid.",
                    requestId,
                    cancellationToken);
            }

            deviceIdForLog = payloadResult.DeviceId.ToString();
            TelemetryPayload validatedPayload = payload!;
            TelemetryPayloadEnricher.ApplyServerMetadata(
                validatedPayload,
                _timeProvider.GetUtcNow(),
                requestId,
                certificateResult.Sha256Fingerprint ??
                    throw new InvalidOperationException(
                        "A valid certificate result must include its SHA-256 fingerprint."),
                certificateResult.IssuerSha256Fingerprint ??
                    throw new InvalidOperationException(
                        "A valid certificate result must include its issuer SHA-256 fingerprint."));

            try
            {
                await _ingestionService.UploadAsync(validatedPayload, cancellationToken);
            }
            catch (RequestFailedException exception) when (
                exception.Status is 408 or 429 || exception.Status >= 500)
            {
                result = "IngestionUnavailable";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.ServiceUnavailable,
                    "Telemetry ingestion is temporarily unavailable.",
                    requestId,
                    cancellationToken);
            }
            catch (RequestFailedException)
            {
                result = "IngestionRejected";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.BadGateway,
                    "Telemetry ingestion failed.",
                    requestId,
                    cancellationToken);
            }
            catch (AuthenticationFailedException)
            {
                result = "IngestionAuthenticationUnavailable";
                return await CreateErrorResponseAsync(
                    request,
                    HttpStatusCode.ServiceUnavailable,
                    "Telemetry ingestion is temporarily unavailable.",
                    requestId,
                    cancellationToken);
            }

            result = "Accepted";
            HttpResponseData response = request.CreateResponse(HttpStatusCode.Accepted);
            await response.WriteAsJsonAsync(
                new { status = "accepted", requestId },
                cancellationToken);
            return response;
        }
        finally
        {
            certificate?.Dispose();
            stopwatch.Stop();
            BrokerLog.TelemetryRequestCompleted(
                _logger,
                requestId,
                deviceIdForLog,
                certificateSuffix,
                result,
                stopwatch.Elapsed.TotalMilliseconds);
        }
    }

    private static bool TryGetSingleHeader(
        HttpRequestData request,
        string name,
        out string? value)
    {
        value = null;
        if (!request.Headers.TryGetValues(name, out IEnumerable<string>? values))
        {
            return false;
        }

        string[] materialized = values.ToArray();
        if (materialized.Length != 1 || string.IsNullOrWhiteSpace(materialized[0]))
        {
            return false;
        }

        value = materialized[0];
        return true;
    }

    private static bool HasJsonContentType(HttpRequestData request)
    {
        if (!TryGetSingleHeader(request, "Content-Type", out string? contentType) ||
            !MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? parsed))
        {
            return false;
        }

        return string.Equals(parsed.MediaType, "application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasOversizedContentLength(HttpRequestData request, int maximumBytes)
    {
        if (!TryGetSingleHeader(request, "Content-Length", out string? value))
        {
            return false;
        }

        return !long.TryParse(value, out long contentLength) ||
               contentLength < 0 ||
               contentLength > maximumBytes;
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(
        Stream body,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(body);

        using var output = new MemoryStream(Math.Min(maximumBytes, 16 * 1024));
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(maximumBytes + 1, 16 * 1024));
        try
        {
            while (true)
            {
                int remaining = maximumBytes - checked((int)output.Length);
                int read = await body.ReadAsync(
                    buffer.AsMemory(0, Math.Min(buffer.Length, remaining + 1)),
                    cancellationToken);
                if (read == 0)
                {
                    return output.ToArray();
                }

                if (read > remaining)
                {
                    throw new PayloadTooLargeException();
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<HttpResponseData> CreateErrorResponseAsync(
        HttpRequestData request,
        HttpStatusCode statusCode,
        string error,
        string requestId,
        CancellationToken cancellationToken)
    {
        HttpResponseData response = request.CreateResponse(statusCode);
        await response.WriteAsJsonAsync(new { error, requestId }, cancellationToken);
        return response;
    }

    private sealed class PayloadTooLargeException : Exception;
}

internal static partial class BrokerLog
{
    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Information,
        Message = "Telemetry request completed RequestId={RequestId} DeviceId={DeviceId} " +
                  "CertificateSuffix={CertificateSuffix} Result={Result} " +
                  "ElapsedMilliseconds={ElapsedMilliseconds}")]
    public static partial void TelemetryRequestCompleted(
        ILogger logger,
        string requestId,
        string? deviceId,
        string? certificateSuffix,
        string result,
        double elapsedMilliseconds);
}
