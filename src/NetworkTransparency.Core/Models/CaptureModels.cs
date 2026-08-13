namespace NetworkTransparency.Core.Models;

public sealed record CaptureOptions(bool IncludeDns = true);

public enum CaptureState
{
    Idle,
    Starting,
    Active,
    Stopping,
    Faulted
}

public sealed record CaptureStatus(
    CaptureState State,
    string Message,
    bool KernelProviderActive,
    bool DnsProviderActive,
    Exception? Error = null);

public sealed record CaptureLoadResult(
    IReadOnlyList<NetworkEvent> Events,
    int MalformedLineCount,
    int EmptyLineCount,
    string Path);

public sealed record TrafficAggregate(
    string Key,
    long Events,
    long BytesSent,
    long BytesReceived)
{
    public long TotalBytes => BytesSent + BytesReceived;
}

public sealed record CaptureSummary(
    long EventCount,
    long BytesSent,
    long BytesReceived,
    DateTime? StartedUtc,
    DateTime? EndedUtc,
    TimeSpan Duration,
    IReadOnlyList<TrafficAggregate> TopProcesses,
    IReadOnlyList<TrafficAggregate> TopRemoteHosts,
    IReadOnlyList<TrafficAggregate> TopCategories,
    IReadOnlyList<TrafficAggregate> TopServices);
