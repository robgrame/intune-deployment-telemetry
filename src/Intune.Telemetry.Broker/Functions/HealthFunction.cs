using System.Net;
using System.Reflection;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace Intune.Telemetry.Broker.Functions;

public sealed class HealthFunction
{
    private static readonly string Version =
        typeof(HealthFunction).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ??
        typeof(HealthFunction).Assembly.GetName().Version?.ToString() ??
        "unknown";

    [Function("GetHealth")]
    public static async Task<HttpResponseData> RunAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "health")] HttpRequestData request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        HttpResponseData response = request.CreateResponse(HttpStatusCode.OK);
        await response.WriteAsJsonAsync(new { status = "healthy", version = Version }, cancellationToken);
        return response;
    }
}
