using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using NetworkTransparency.Core.Correlation;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Capture;

internal sealed class EventAggregator : IDisposable
{
    private readonly IEventSink _sink;
    private readonly DnsCache _dnsCache = new();
    private readonly ServiceResolver _serviceResolver = new();
    private readonly TaskSchedulerResolver _taskResolver = new();
    private readonly ProcessMetadataResolver _processResolver = new();
    private readonly ConcurrentDictionary<int, ProcessCacheEntry> _processCache = new();
    private readonly ConcurrentDictionary<string, FlowTracker> _flows = new();
    private readonly Channel<RawNetworkEvent> _eventQueue;
    private readonly Task _enrichmentTask;
    private long _droppedEventCount;

    public EventAggregator(IEventSink sink)
    {
        _sink = sink;
        _eventQueue = Channel.CreateBounded<RawNetworkEvent>(new BoundedChannelOptions(16_384)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        _enrichmentTask = Task.Run(ProcessQueueAsync);
    }

    public event EventHandler<DnsObservation>? DnsObserved;
    public event Action<Exception>? PipelineFaulted;

    public long DroppedEventCount => Interlocked.Read(ref _droppedEventCount);

    public void OnTcpConnect(TcpIpConnectTraceData data)
    {
        if (data.ProcessID <= 0)
        {
            return;
        }

        var timestamp = data.TimeStamp.ToUniversalTime();
        var tracker = _flows.GetOrAdd(
            FlowKey(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP"),
            _ => new FlowTracker(timestamp));

        EnqueueEvent(timestamp, data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
            "TCP", tracker.BytesSent, tracker.BytesReceived, "Outbound", "connect");
    }

    public void OnTcpSend(TcpIpSendTraceData data) => TrackBytes(
        data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
        "TCP", data.size, 0, data.TimeStamp.ToUniversalTime(), "Outbound", "send");

    public void OnTcpRecv(TcpIpTraceData data) => TrackBytes(
        data.ProcessID, data.daddr, data.dport, data.saddr, data.sport,
        "TCP", 0, data.size, data.TimeStamp.ToUniversalTime(), "Inbound", "receive");

    public void OnUdpSend(UdpIpTraceData data) => TrackBytes(
        data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
        "UDP", data.size, 0, data.TimeStamp.ToUniversalTime(), "Outbound", "send");

    public void OnUdpRecv(UdpIpTraceData data) => TrackBytes(
        data.ProcessID, data.daddr, data.dport, data.saddr, data.sport,
        "UDP", 0, data.size, data.TimeStamp.ToUniversalTime(), "Inbound", "receive");

    public void OnTcpConnectV6(TcpIpV6ConnectTraceData data)
    {
        if (data.ProcessID <= 0)
        {
            return;
        }

        var timestamp = data.TimeStamp.ToUniversalTime();
        var tracker = _flows.GetOrAdd(
            FlowKey(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP"),
            _ => new FlowTracker(timestamp));

        EnqueueEvent(timestamp, data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
            "TCP", tracker.BytesSent, tracker.BytesReceived, "Outbound", "connect (IPv6)");
    }

    public void OnTcpSendV6(TcpIpV6SendTraceData data) => TrackBytes(
        data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
        "TCP", data.size, 0, data.TimeStamp.ToUniversalTime(), "Outbound", "send (IPv6)");

    public void OnTcpRecvV6(TcpIpV6TraceData data) => TrackBytes(
        data.ProcessID, data.daddr, data.dport, data.saddr, data.sport,
        "TCP", 0, data.size, data.TimeStamp.ToUniversalTime(), "Inbound", "receive (IPv6)");

    public void OnUdpSendV6(UpdIpV6TraceData data) => TrackBytes(
        data.ProcessID, data.saddr, data.sport, data.daddr, data.dport,
        "UDP", data.size, 0, data.TimeStamp.ToUniversalTime(), "Outbound", "send (IPv6)");

    public void OnUdpRecvV6(UpdIpV6TraceData data) => TrackBytes(
        data.ProcessID, data.daddr, data.dport, data.saddr, data.sport,
        "UDP", 0, data.size, data.TimeStamp.ToUniversalTime(), "Inbound", "receive (IPv6)");

    public void OnDnsQuery(TraceEvent data)
    {
        var queryName = Payload(data, "QueryName", "Query")?.ToString();
        if (string.IsNullOrWhiteSpace(queryName))
        {
            return;
        }

        var timestamp = data.TimeStamp.ToUniversalTime();
        _dnsCache.TrackQuery(queryName, timestamp);
        DnsObserved?.Invoke(this, new DnsObservation(
            timestamp,
            data.ProcessID,
            queryName,
            null,
            DnsObservationKind.Query,
            "Observed query"));
    }

    public void OnDnsResponse(TraceEvent data)
    {
        var queryName = Payload(data, "QueryName", "Query")?.ToString();
        var addresses = ParseAddresses(Payload(data, "Address", "QueryResults", "Result"));
        if (string.IsNullOrWhiteSpace(queryName))
        {
            return;
        }

        var timestamp = data.TimeStamp.ToUniversalTime();
        foreach (var address in addresses)
        {
            _dnsCache.TrackResponse(address, queryName, timestamp);
            DnsObserved?.Invoke(this, new DnsObservation(
                timestamp,
                data.ProcessID,
                queryName,
                address.ToString(),
                DnsObservationKind.Response,
                "Observed response"));
        }
    }

    private void TrackBytes(
        int pid,
        IPAddress localIp,
        int localPort,
        IPAddress remoteIp,
        int remotePort,
        string protocol,
        long bytesSent,
        long bytesReceived,
        DateTime timestampUtc,
        string direction,
        string note)
    {
        if (pid <= 0)
        {
            return;
        }

        var flowKey = FlowKey(pid, localIp, localPort, remoteIp, remotePort, protocol);
        var tracker = _flows.GetOrAdd(flowKey, _ => new FlowTracker(timestampUtc));
        tracker.Update(bytesSent, bytesReceived, timestampUtc);

        EnqueueEvent(timestampUtc, pid, localIp, localPort, remoteIp, remotePort, protocol,
            tracker.BytesSent, tracker.BytesReceived, direction, note);
    }

    private void EnqueueEvent(
        DateTime timestampUtc,
        int pid,
        IPAddress localIp,
        int localPort,
        IPAddress remoteIp,
        int remotePort,
        string protocol,
        long bytesSent,
        long bytesReceived,
        string direction,
        string note)
    {
        var queued = _eventQueue.Writer.TryWrite(new RawNetworkEvent(
            timestampUtc,
            pid,
            localIp,
            localPort,
            remoteIp,
            remotePort,
            protocol,
            bytesSent,
            bytesReceived,
            direction,
            note));

        if (!queued)
        {
            Interlocked.Increment(ref _droppedEventCount);
        }

        PruneFlows(timestampUtc);
    }

    private async Task ProcessQueueAsync()
    {
        await foreach (var rawEvent in _eventQueue.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            NetworkEvent enriched;
            try
            {
                enriched = Enrich(rawEvent);
            }
            catch
            {
                // A single metadata lookup must never terminate the capture pipeline.
                continue;
            }

            try
            {
                _sink.Write(enriched);
            }
            catch (Exception error)
            {
                PipelineFaulted?.Invoke(error);
                return;
            }
        }
    }

    private NetworkEvent Enrich(RawNetworkEvent rawEvent)
    {
        var timestampUtc = rawEvent.TimestampUtc;
        var pid = rawEvent.Pid;
        var remoteIp = rawEvent.RemoteIp;
        var process = ResolveProcess(pid, timestampUtc);
        var services = _serviceResolver.Resolve(pid);
        var dns = _dnsCache.Resolve(remoteIp, timestampUtc);
        var taskCorrelations = _taskResolver.GetTasksNear(timestampUtc);
        var classification = Classifier.Classify(process, services.Select(service => service.Name).ToArray(), dns.Names);

        return new NetworkEvent(
            timestampUtc,
            pid,
            process.ProcessName,
            process.User,
            services.Select(service => service.Name).ToArray(),
            rawEvent.LocalIp.ToString(),
            rawEvent.LocalPort,
            remoteIp.ToString(),
            rawEvent.RemotePort,
            rawEvent.Protocol,
            rawEvent.BytesSent,
            rawEvent.BytesReceived,
            dns.Names,
            null,
            classification.Category,
            classification.Confidence,
            taskCorrelations.Select(task => task.Path).ToArray(),
            $"{rawEvent.Note}; classification: {classification.Reason}",
            process,
            services,
            rawEvent.Direction,
            "Microsoft-Windows-Kernel-Network",
            dns.State,
            taskCorrelations);
    }

    private void PruneFlows(DateTime timestampUtc)
    {
        if (_flows.Count <= 4096 || _flows.Count % 128 != 0)
        {
            return;
        }

        foreach (var flow in _flows.Where(pair => timestampUtc - pair.Value.LastSeenUtc > TimeSpan.FromMinutes(10)))
        {
            _flows.TryRemove(flow.Key, out _);
        }
    }

    private ProcessMetadata ResolveProcess(int pid, DateTime timestampUtc)
    {
        if (_processCache.TryGetValue(pid, out var cached) &&
            timestampUtc - cached.ResolvedUtc < TimeSpan.FromSeconds(30))
        {
            return cached.Metadata;
        }

        var metadata = _processResolver.Resolve(pid);
        _processCache[pid] = new ProcessCacheEntry(timestampUtc, metadata);

        if (_processCache.Count > 2_048)
        {
            foreach (var entry in _processCache.Where(pair => timestampUtc - pair.Value.ResolvedUtc > TimeSpan.FromMinutes(10)))
            {
                _processCache.TryRemove(entry.Key, out _);
            }
        }

        return metadata;
    }

    private static object? Payload(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                if (value is not null)
                {
                    return value;
                }
            }
            catch
            {
            }
        }

        return null;
    }

    private static IReadOnlyList<IPAddress> ParseAddresses(object? payload)
    {
        if (payload is IPAddress address)
        {
            return new[] { address };
        }

        var text = payload?.ToString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return Array.Empty<IPAddress>();
        }

        return text.Split(new[] { ';', ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(token => token.Trim('[', ']', '.'))
            .Select(token => IPAddress.TryParse(token, out var parsed) ? parsed : null)
            .OfType<IPAddress>()
            .Distinct()
            .ToArray();
    }

    private static string FlowKey(
        int pid,
        IPAddress localIp,
        int localPort,
        IPAddress remoteIp,
        int remotePort,
        string protocol) =>
        $"{pid}:{localIp}:{localPort}->{remoteIp}:{remotePort}:{protocol}";

    public void Dispose()
    {
        _eventQueue.Writer.TryComplete();
        try
        {
            _enrichmentTask.Wait(TimeSpan.FromSeconds(10));
        }
        catch
        {
        }
    }

    private sealed record RawNetworkEvent(
        DateTime TimestampUtc,
        int Pid,
        IPAddress LocalIp,
        int LocalPort,
        IPAddress RemoteIp,
        int RemotePort,
        string Protocol,
        long BytesSent,
        long BytesReceived,
        string Direction,
        string Note);

    private sealed record ProcessCacheEntry(DateTime ResolvedUtc, ProcessMetadata Metadata);

    private sealed class FlowTracker
    {
        private long _bytesSent;
        private long _bytesReceived;
        private long _lastSeenTicks;

        public FlowTracker(DateTime timestampUtc)
        {
            _lastSeenTicks = timestampUtc.Ticks;
        }

        public long BytesSent => Interlocked.Read(ref _bytesSent);
        public long BytesReceived => Interlocked.Read(ref _bytesReceived);
        public DateTime LastSeenUtc => new(Interlocked.Read(ref _lastSeenTicks), DateTimeKind.Utc);

        public void Update(long bytesSent, long bytesReceived, DateTime timestampUtc)
        {
            Interlocked.Add(ref _bytesSent, bytesSent);
            Interlocked.Add(ref _bytesReceived, bytesReceived);
            Interlocked.Exchange(ref _lastSeenTicks, timestampUtc.Ticks);
        }
    }
}
