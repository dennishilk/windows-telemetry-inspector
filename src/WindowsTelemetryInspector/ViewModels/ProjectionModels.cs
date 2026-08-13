using NetworkTransparency.Core.Analysis;
using NetworkTransparency.Core.Models;

namespace WindowsTelemetryInspector.ViewModels;

public sealed record ProcessAggregateRow(
    int Pid,
    string ProcessName,
    long EventCount,
    long BytesSent,
    long BytesReceived,
    int RemoteHostCount,
    string Services,
    string DominantCategory,
    ProcessMetadata Metadata)
{
    public long TotalBytes => BytesSent + BytesReceived;
}

public sealed record ServiceAggregateRow(
    string Name,
    string DisplayName,
    string State,
    long EventCount,
    long BytesSent,
    long BytesReceived,
    int ProcessCount,
    string DominantCategory)
{
    public long TotalBytes => BytesSent + BytesReceived;
}

public sealed record TimelineBucketRow(
    DateTime StartedUtc,
    TimeSpan Resolution,
    long EventCount,
    long BytesSent,
    long BytesReceived,
    string DominantCategory,
    string DominantProcess,
    double Intensity)
{
    public long TotalBytes => BytesSent + BytesReceived;
}

public sealed record CaptureFileRow(
    string Name,
    string FullPath,
    long Size,
    DateTime ModifiedLocal);

internal static class ProjectionBuilder
{
    public static IReadOnlyList<ProcessAggregateRow> Processes(IEnumerable<NetworkEvent> events)
    {
        var aggregates = new Dictionary<(int Pid, string Name), MutableProcess>();
        foreach (var item in CaptureAnalyzer.CalculateDeltas(events))
        {
            var networkEvent = item.Event;
            var key = (networkEvent.Pid, networkEvent.ProcessName);
            if (!aggregates.TryGetValue(key, out var aggregate))
            {
                aggregate = new MutableProcess(networkEvent.Process ?? ProcessMetadata.Unknown(networkEvent.Pid));
                aggregates[key] = aggregate;
            }

            aggregate.Events++;
            aggregate.Sent += item.BytesSent;
            aggregate.Received += item.BytesReceived;
            aggregate.Hosts.Add(networkEvent.RemoteHost == "Not resolved" ? networkEvent.RemoteIp : networkEvent.RemoteHost);
            foreach (var service in networkEvent.ServiceNames)
            {
                aggregate.Services.Add(service);
            }

            Increment(aggregate.Categories, networkEvent.Classification);
            if (networkEvent.Process is not null && networkEvent.TimestampUtc >= aggregate.MetadataTimestamp)
            {
                aggregate.Metadata = networkEvent.Process;
                aggregate.MetadataTimestamp = networkEvent.TimestampUtc;
            }
        }

        return aggregates
            .Select(pair => new ProcessAggregateRow(
                pair.Key.Pid,
                pair.Key.Name,
                pair.Value.Events,
                pair.Value.Sent,
                pair.Value.Received,
                pair.Value.Hosts.Count,
                pair.Value.Services.Count == 0 ? "No associated service" : string.Join(", ", pair.Value.Services.OrderBy(value => value)),
                Dominant(pair.Value.Categories),
                pair.Value.Metadata))
            .OrderByDescending(row => row.TotalBytes)
            .ThenByDescending(row => row.EventCount)
            .ToArray();
    }

    public static IReadOnlyList<ServiceAggregateRow> Services(IEnumerable<NetworkEvent> events)
    {
        var aggregates = new Dictionary<string, MutableService>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in CaptureAnalyzer.CalculateDeltas(events))
        {
            var networkEvent = item.Event;
            var serviceDetails = networkEvent.ServiceDetails;
            if (serviceDetails.Count == 0 && networkEvent.ServiceNames.Count > 0)
            {
                serviceDetails = networkEvent.ServiceNames
                    .Select(name => new ServiceInfo(name, "Not available", "Unknown"))
                    .ToArray();
            }

            foreach (var service in serviceDetails)
            {
                if (!aggregates.TryGetValue(service.Name, out var aggregate))
                {
                    aggregate = new MutableService(service.DisplayName, service.State);
                    aggregates[service.Name] = aggregate;
                }

                aggregate.Events++;
                aggregate.Sent += item.BytesSent;
                aggregate.Received += item.BytesReceived;
                aggregate.Pids.Add(networkEvent.Pid);
                Increment(aggregate.Categories, networkEvent.Classification);
                if (!service.DisplayName.Equals("Not available", StringComparison.OrdinalIgnoreCase))
                {
                    aggregate.DisplayName = service.DisplayName;
                }

                if (!service.State.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    aggregate.State = service.State;
                }
            }
        }

        return aggregates
            .Select(pair => new ServiceAggregateRow(
                pair.Key,
                pair.Value.DisplayName,
                pair.Value.State,
                pair.Value.Events,
                pair.Value.Sent,
                pair.Value.Received,
                pair.Value.Pids.Count,
                Dominant(pair.Value.Categories)))
            .OrderByDescending(row => row.TotalBytes)
            .ThenByDescending(row => row.EventCount)
            .ToArray();
    }

    public static IReadOnlyList<TimelineBucketRow> Timeline(IEnumerable<NetworkEvent> events)
    {
        var traffic = CaptureAnalyzer.CalculateDeltas(events);
        if (traffic.Count == 0)
        {
            return Array.Empty<TimelineBucketRow>();
        }

        var duration = traffic[^1].Event.TimestampUtc - traffic[0].Event.TimestampUtc;
        var resolution = duration switch
        {
            { TotalHours: <= 2 } => TimeSpan.FromMinutes(1),
            { TotalHours: <= 12 } => TimeSpan.FromMinutes(5),
            { TotalDays: <= 2 } => TimeSpan.FromMinutes(15),
            _ => TimeSpan.FromHours(1)
        };

        var buckets = new SortedDictionary<DateTime, MutableTimeline>();
        foreach (var item in traffic)
        {
            var start = Floor(item.Event.TimestampUtc, resolution);
            if (!buckets.TryGetValue(start, out var bucket))
            {
                bucket = new MutableTimeline();
                buckets[start] = bucket;
            }

            bucket.Events++;
            bucket.Sent += item.BytesSent;
            bucket.Received += item.BytesReceived;
            Increment(bucket.Categories, item.Event.Classification);
            Increment(bucket.Processes, $"{item.Event.ProcessName} ({item.Event.Pid})");
        }

        var maximum = Math.Max(1L, buckets.Values.Max(bucket => bucket.Sent + bucket.Received));
        return buckets
            .TakeLast(240)
            .Select(pair => new TimelineBucketRow(
                pair.Key,
                resolution,
                pair.Value.Events,
                pair.Value.Sent,
                pair.Value.Received,
                Dominant(pair.Value.Categories),
                Dominant(pair.Value.Processes),
                Math.Max(2, (pair.Value.Sent + pair.Value.Received) * 100d / maximum)))
            .ToArray();
    }

    private static DateTime Floor(DateTime value, TimeSpan resolution)
    {
        var ticks = value.Ticks / resolution.Ticks * resolution.Ticks;
        return new DateTime(ticks, value.Kind);
    }

    private static void Increment(Dictionary<string, long> counts, string? key)
    {
        var normalized = string.IsNullOrWhiteSpace(key) ? "Other" : key;
        counts.TryGetValue(normalized, out var count);
        counts[normalized] = count + 1;
    }

    private static string Dominant(Dictionary<string, long> categories) =>
        categories.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key).FirstOrDefault().Key ?? "Other";

    private sealed class MutableProcess
    {
        public MutableProcess(ProcessMetadata metadata)
        {
            Metadata = metadata;
        }

        public long Events { get; set; }
        public long Sent { get; set; }
        public long Received { get; set; }
        public HashSet<string> Hosts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, long> Categories { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ProcessMetadata Metadata { get; set; }
        public DateTime MetadataTimestamp { get; set; }
    }

    private sealed class MutableService
    {
        public MutableService(string displayName, string state)
        {
            DisplayName = displayName;
            State = state;
        }

        public string DisplayName { get; set; }
        public string State { get; set; }
        public long Events { get; set; }
        public long Sent { get; set; }
        public long Received { get; set; }
        public HashSet<int> Pids { get; } = new();
        public Dictionary<string, long> Categories { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class MutableTimeline
    {
        public long Events { get; set; }
        public long Sent { get; set; }
        public long Received { get; set; }
        public Dictionary<string, long> Categories { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, long> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
