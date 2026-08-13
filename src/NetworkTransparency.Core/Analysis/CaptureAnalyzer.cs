using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Analysis;

public static class CaptureAnalyzer
{
    public static IReadOnlyList<EventTraffic> CalculateDeltas(IEnumerable<NetworkEvent> source)
    {
        var previousByFlow = new Dictionary<string, FlowBytes>(StringComparer.Ordinal);
        var result = new List<EventTraffic>();

        foreach (var networkEvent in source.OrderBy(item => item.TimestampUtc))
        {
            var flowKey = FlowKey(networkEvent);
            previousByFlow.TryGetValue(flowKey, out var previous);
            var sentDelta = Delta(previous.Sent, networkEvent.BytesSent);
            var receivedDelta = Delta(previous.Received, networkEvent.BytesRecv);
            previousByFlow[flowKey] = new FlowBytes(networkEvent.BytesSent, networkEvent.BytesRecv);
            result.Add(new EventTraffic(networkEvent, sentDelta, receivedDelta));
        }

        return result;
    }

    public static CaptureSummary Summarize(IEnumerable<NetworkEvent> source, int top = 10)
    {
        var events = source.OrderBy(networkEvent => networkEvent.TimestampUtc).ToArray();
        if (events.Length == 0)
        {
            return new CaptureSummary(
                0,
                0,
                0,
                null,
                null,
                TimeSpan.Zero,
                Array.Empty<TrafficAggregate>(),
                Array.Empty<TrafficAggregate>(),
                Array.Empty<TrafficAggregate>(),
                Array.Empty<TrafficAggregate>());
        }

        var process = new Dictionary<string, MutableAggregate>(StringComparer.OrdinalIgnoreCase);
        var remote = new Dictionary<string, MutableAggregate>(StringComparer.OrdinalIgnoreCase);
        var category = new Dictionary<string, MutableAggregate>(StringComparer.OrdinalIgnoreCase);
        var service = new Dictionary<string, MutableAggregate>(StringComparer.OrdinalIgnoreCase);
        long sentTotal = 0;
        long receivedTotal = 0;

        foreach (var eventTraffic in CalculateDeltas(events))
        {
            var networkEvent = eventTraffic.Event;
            var sentDelta = eventTraffic.BytesSent;
            var receivedDelta = eventTraffic.BytesReceived;

            sentTotal += sentDelta;
            receivedTotal += receivedDelta;

            Add(process, $"{networkEvent.ProcessName} ({networkEvent.Pid})", sentDelta, receivedDelta);
            Add(remote, networkEvent.RemoteHost == "Not resolved" ? networkEvent.RemoteIp : networkEvent.RemoteHost, sentDelta, receivedDelta);
            Add(category, networkEvent.Classification, sentDelta, receivedDelta);

            if (networkEvent.ServiceNames.Count == 0)
            {
                Add(service, "No associated service", sentDelta, receivedDelta);
            }
            else
            {
                foreach (var serviceName in networkEvent.ServiceNames.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    Add(service, serviceName, sentDelta, receivedDelta);
                }
            }
        }

        var started = events[0].TimestampUtc;
        var ended = events[^1].TimestampUtc;
        return new CaptureSummary(
            events.LongLength,
            sentTotal,
            receivedTotal,
            started,
            ended,
            ended - started,
            Freeze(process, top),
            Freeze(remote, top),
            Freeze(category, top),
            Freeze(service, top));
    }

    private static long Delta(long previous, long current)
    {
        var safeCurrent = Math.Max(0, current);
        return safeCurrent >= previous ? safeCurrent - previous : safeCurrent;
    }

    private static string FlowKey(NetworkEvent networkEvent) =>
        $"{networkEvent.Pid}|{networkEvent.LocalIp}|{networkEvent.LocalPort}|{networkEvent.RemoteIp}|{networkEvent.RemotePort}|{networkEvent.Protocol}";

    private static void Add(Dictionary<string, MutableAggregate> target, string? key, long sent, long received)
    {
        var normalized = string.IsNullOrWhiteSpace(key) ? "Unknown" : key;
        if (!target.TryGetValue(normalized, out var aggregate))
        {
            aggregate = new MutableAggregate();
            target[normalized] = aggregate;
        }

        aggregate.Events++;
        aggregate.Sent += sent;
        aggregate.Received += received;
    }

    private static IReadOnlyList<TrafficAggregate> Freeze(Dictionary<string, MutableAggregate> source, int top) =>
        source
            .Select(pair => new TrafficAggregate(pair.Key, pair.Value.Events, pair.Value.Sent, pair.Value.Received))
            .OrderByDescending(aggregate => aggregate.TotalBytes)
            .ThenByDescending(aggregate => aggregate.Events)
            .ThenBy(aggregate => aggregate.Key, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(0, top))
            .ToArray();

    private sealed class MutableAggregate
    {
        public long Events { get; set; }
        public long Sent { get; set; }
        public long Received { get; set; }
    }

    private readonly record struct FlowBytes(long Sent, long Received);
}

public sealed record EventTraffic(NetworkEvent Event, long BytesSent, long BytesReceived)
{
    public long TotalBytes => BytesSent + BytesReceived;
}
