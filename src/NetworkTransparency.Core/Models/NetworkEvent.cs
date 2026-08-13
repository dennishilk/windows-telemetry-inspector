using System.Text.Json.Serialization;

namespace NetworkTransparency.Core.Models;

public sealed record NetworkEvent(
    DateTime TimestampUtc,
    int Pid,
    string ProcessName,
    string User,
    IReadOnlyList<string> ServiceNames,
    string LocalIp,
    int LocalPort,
    string RemoteIp,
    int RemotePort,
    string Protocol,
    long BytesSent,
    long BytesRecv,
    IReadOnlyList<string> DnsNames,
    string? SniHost,
    string Classification,
    double Confidence,
    IReadOnlyList<string> RelatedTasks,
    string Notes,
    ProcessMetadata? Process = null,
    IReadOnlyList<ServiceInfo>? Services = null,
    string Direction = "Unknown",
    string EtwProvider = "Not available",
    DnsCorrelationState DnsCorrelation = DnsCorrelationState.NotResolved,
    IReadOnlyList<TaskCorrelation>? TaskCorrelations = null)
{
    [JsonIgnore]
    public string LocalEndpoint => $"{LocalIp}:{LocalPort}";

    [JsonIgnore]
    public string RemoteEndpoint => $"{RemoteIp}:{RemotePort}";

    [JsonIgnore]
    public string RemoteHost => DnsNames.FirstOrDefault() ?? "Not resolved";

    [JsonIgnore]
    public IReadOnlyList<ServiceInfo> ServiceDetails => Services ?? Array.Empty<ServiceInfo>();

    [JsonIgnore]
    public IReadOnlyList<TaskCorrelation> CorrelatedTasks => TaskCorrelations ?? Array.Empty<TaskCorrelation>();

    [JsonIgnore]
    public int ConfidencePercent => (int)Math.Round(Math.Clamp(Confidence, 0, 1) * 100);
}

public enum DnsCorrelationState
{
    NotResolved,
    CorrelatedResponse,
    Cached,
    Unavailable
}

public sealed record ProcessMetadata(
    int Pid,
    string ProcessName,
    string User,
    string Description,
    string Company,
    string ExecutablePath,
    string CommandLine,
    int? ParentPid,
    string ParentProcess,
    DateTime? StartTimeUtc,
    string IntegrityLevel,
    string Signer)
{
    public static ProcessMetadata Unknown(int pid) => new(
        pid,
        "Unknown",
        "Unknown",
        "Not available",
        "Not available",
        "Not available",
        "Not available",
        null,
        "Not resolved",
        null,
        "Not available",
        "Not resolved");
}

public sealed record ServiceInfo(string Name, string DisplayName, string State);

public sealed record DnsObservation(
    DateTime TimestampUtc,
    int Pid,
    string QueryName,
    string? Address,
    DnsObservationKind Kind,
    string Status);

public enum DnsObservationKind
{
    Query,
    Response
}

public sealed record TaskCorrelation(
    string Name,
    string Path,
    DateTime? LastRunUtc,
    TimeSpan? Distance,
    string State)
{
    [JsonIgnore]
    public string DistanceDisplay => Distance.HasValue ? Distance.Value.ToString("g") : "Not available";
}
