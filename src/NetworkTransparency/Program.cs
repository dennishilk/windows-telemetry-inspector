using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetworkTransparency;

internal static class Program
{

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var options = CliOptions.Parse(args.Skip(1).ToArray());

        try
        {
            switch (command)
            {
                case "live":
                    await RunLiveAsync(options);
                    return 0;
                case "record":
                    if (string.IsNullOrWhiteSpace(options.OutputPath))
                    {
                        Console.Error.WriteLine("record requires --output <path>.");
                        return 2;
                    }

                    await RunRecordAsync(options);
                    return 0;
                case "summary":
                    if (string.IsNullOrWhiteSpace(options.InputPath))
                    {
                        Console.Error.WriteLine("summary requires --input <path>.");
                        return 2;
                    }

                    RunSummary(options.InputPath!);
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown command: {command}");
                    PrintHelp();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Network Transparency (Windows 11)\n");
        Console.WriteLine("Usage:");
        Console.WriteLine("  network-transparency live [--duration <seconds>] [--include-dns]");
        Console.WriteLine("  network-transparency record --output <path> [--duration <seconds>] [--include-dns]");
        Console.WriteLine("  network-transparency summary --input <path>");
    }

    private static async Task RunLiveAsync(CliOptions options)
    {
        using var writer = new LiveWriter(Console.Out);
        await RunSessionAsync(options, writer);
    }

    private static async Task RunRecordAsync(CliOptions options)
    {
        using var stream = new FileStream(options.OutputPath!, FileMode.Create, FileAccess.Write, FileShare.Read);
        using var writer = new JsonlWriter(stream);
        await RunSessionAsync(options, writer);
    }

    private static async Task RunSessionAsync(CliOptions options, IEventWriter writer)
    {
        var aggregator = new EventAggregator(writer);
        using var session = CreateSession(aggregator, options.IncludeDns);

        if (!session.IsActive)
        {
            Console.Error.WriteLine("ETW session could not start. Try running as Administrator.");
            return;
        }

        Console.WriteLine("Starting capture. Press Ctrl+C to stop.");
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };

        if (options.DurationSeconds.HasValue)
        {
            cts.CancelAfter(TimeSpan.FromSeconds(options.DurationSeconds.Value));
        }

        await Task.Run(() => session.Source.Process(), cts.Token);
    }

    private static void RunSummary(string inputPath)
    {
        SummaryReport.Run(inputPath);
    }

    private static TraceEventSession CreateSession(EventAggregator aggregator, bool includeDns)
    {
        var sessionName = $"NetworkTransparency-{Guid.NewGuid():N}";
        var session = new TraceEventSession(sessionName)
        {
            StopOnDispose = true
        };

        try
        {
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Insufficient privileges to enable kernel network provider.");
        }

        if (includeDns)
        {
            try
            {
                session.EnableProvider("Microsoft-Windows-DNS-Client");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to enable DNS provider: {ex.Message}");
            }
        }

        var kernelParser = new KernelTraceEventParser(session.Source);
        kernelParser.TcpIpConnect += aggregator.OnTcpConnect;
        kernelParser.TcpIpRecv += aggregator.OnTcpRecv;
        kernelParser.TcpIpSend += aggregator.OnTcpSend;
        kernelParser.UdpIpSend += aggregator.OnUdpSend;
        kernelParser.UdpIpRecv += aggregator.OnUdpRecv;

        if (includeDns)
        {
            var dnsParser = new DynamicTraceEventParser(session.Source);
            dnsParser.AddCallbackForProviderEvent("Microsoft-Windows-DNS-Client", "DnsQuery", aggregator.OnDnsQuery);
            dnsParser.AddCallbackForProviderEvent("Microsoft-Windows-DNS-Client", "DnsResponse", aggregator.OnDnsResponse);
        }

        return session;
    }
}

internal sealed class CliOptions
{
    public string? OutputPath { get; init; }
    public string? InputPath { get; init; }
    public int? DurationSeconds { get; init; }
    public bool IncludeDns { get; init; }

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "--output":
                    options.OutputPath = args.ElementAtOrDefault(++i);
                    break;
                case "--input":
                    options.InputPath = args.ElementAtOrDefault(++i);
                    break;
                case "--duration":
                    if (int.TryParse(args.ElementAtOrDefault(++i), out var duration))
                    {
                        options.DurationSeconds = duration;
                    }
                    break;
                case "--include-dns":
                    options.IncludeDns = true;
                    break;
            }
        }

        return options;
    }
}

internal sealed class EventAggregator
{
    private readonly IEventWriter _writer;
    private readonly DnsCache _dnsCache = new();
    private readonly ServiceResolver _serviceResolver = new();
    private readonly TaskSchedulerResolver _taskResolver = new();
    private readonly ConcurrentDictionary<int, ProcessInfo> _processCache = new();
    private readonly ConcurrentDictionary<string, FlowTracker> _flows = new();

    public EventAggregator(IEventWriter writer)
    {
        _writer = writer;
    }

    public void OnTcpConnect(TcpIpConnectTraceData data)
    {
        if (data.ProcessID <= 0)
        {
            return;
        }

        var flowKey = FlowKey(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP");
        var tracker = _flows.GetOrAdd(flowKey, _ => new FlowTracker(data.TimeStamp.ToUniversalTime()));
        tracker.MarkStart(data.TimeStamp.ToUniversalTime());
        EmitEvent(data.TimeStamp.ToUniversalTime(), data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP", tracker.BytesSent, tracker.BytesReceived, "connect");
    }

    public void OnTcpSend(TcpIpSendTraceData data)
    {
        TrackBytes(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP", data.size, 0, data.TimeStamp.ToUniversalTime(), "send");
    }

    public void OnTcpRecv(TcpIpRecvTraceData data)
    {
        TrackBytes(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "TCP", 0, data.size, data.TimeStamp.ToUniversalTime(), "recv");
    }

    public void OnUdpSend(UdpIpTraceData data)
    {
        TrackBytes(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "UDP", data.size, 0, data.TimeStamp.ToUniversalTime(), "send");
    }

    public void OnUdpRecv(UdpIpTraceData data)
    {
        TrackBytes(data.ProcessID, data.saddr, data.sport, data.daddr, data.dport, "UDP", 0, data.size, data.TimeStamp.ToUniversalTime(), "recv");
    }

    public void OnDnsQuery(TraceEvent data)
    {
        var queryName = data.PayloadByName("QueryName")?.ToString();
        if (string.IsNullOrWhiteSpace(queryName))
        {
            return;
        }

        _dnsCache.TrackQuery(queryName);
    }

    public void OnDnsResponse(TraceEvent data)
    {
        var queryName = data.PayloadByName("QueryName")?.ToString();
        var address = data.PayloadByName("Address")?.ToString();
        if (string.IsNullOrWhiteSpace(queryName) || string.IsNullOrWhiteSpace(address))
        {
            return;
        }

        if (IPAddress.TryParse(address, out var ip))
        {
            _dnsCache.TrackResponse(ip, queryName);
        }
    }

    private void TrackBytes(int pid, IPAddress localIp, int localPort, IPAddress remoteIp, int remotePort, string protocol, long bytesSent, long bytesReceived, DateTime timestampUtc, string note)
    {
        if (pid <= 0)
        {
            return;
        }

        var flowKey = FlowKey(pid, localIp, localPort, remoteIp, remotePort, protocol);
        var tracker = _flows.GetOrAdd(flowKey, _ => new FlowTracker(timestampUtc));
        tracker.Update(bytesSent, bytesReceived, timestampUtc);

        EmitEvent(timestampUtc, pid, localIp, localPort, remoteIp, remotePort, protocol, tracker.BytesSent, tracker.BytesReceived, note);
    }

    private void EmitEvent(DateTime timestampUtc, int pid, IPAddress localIp, int localPort, IPAddress remoteIp, int remotePort, string protocol, long bytesSent, long bytesReceived, string note)
    {
        var processInfo = _processCache.GetOrAdd(pid, ProcessInfo.FromPid);
        var dnsNames = _dnsCache.Resolve(remoteIp);
        var services = _serviceResolver.ResolveServices(pid);
        var tasks = _taskResolver.GetTasksNear(timestampUtc);
        var classification = Classifier.Classify(processInfo, services, dnsNames);

        var networkEvent = new NetworkEvent(
            timestampUtc,
            pid,
            processInfo.ProcessName,
            processInfo.User,
            services,
            localIp.ToString(),
            localPort,
            remoteIp.ToString(),
            remotePort,
            protocol,
            bytesSent,
            bytesReceived,
            dnsNames,
            null,
            classification.Category,
            classification.Confidence,
            tasks,
            note);

        _writer.Write(networkEvent);
    }

    private static string FlowKey(int pid, IPAddress localIp, int localPort, IPAddress remoteIp, int remotePort, string protocol)
    {
        return $"{pid}:{localIp}:{localPort}->{remoteIp}:{remotePort}:{protocol}";
    }
}

internal sealed class FlowTracker
{
    private DateTime _lastSeen;
    public long BytesSent { get; private set; }
    public long BytesReceived { get; private set; }

    public FlowTracker(DateTime timestampUtc)
    {
        _lastSeen = timestampUtc;
    }

    public void MarkStart(DateTime timestampUtc)
    {
        _lastSeen = timestampUtc;
    }

    public void Update(long bytesSent, long bytesReceived, DateTime timestampUtc)
    {
        BytesSent += bytesSent;
        BytesReceived += bytesReceived;
        _lastSeen = timestampUtc;
    }
}

internal sealed record NetworkEvent(
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
    string Notes);

internal static class SerializerOptions
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}

internal interface IEventWriter : IDisposable
{
    void Write(NetworkEvent networkEvent);
}

internal sealed class JsonlWriter : IEventWriter
{
    private readonly StreamWriter _writer;

    public JsonlWriter(Stream stream)
    {
        _writer = new StreamWriter(stream) { AutoFlush = true };
    }

    public void Write(NetworkEvent networkEvent)
    {
        var json = JsonSerializer.Serialize(networkEvent, SerializerOptions.Options);
        _writer.WriteLine(json);
    }

    public void Dispose()
    {
        _writer.Dispose();
    }
}

internal sealed class LiveWriter : IEventWriter
{
    private readonly TextWriter _writer;

    public LiveWriter(TextWriter writer)
    {
        _writer = writer;
    }

    public void Write(NetworkEvent networkEvent)
    {
        var json = JsonSerializer.Serialize(networkEvent, SerializerOptions.Options);
        _writer.WriteLine(json);
    }

    public void Dispose()
    {
    }
}

internal sealed record ProcessInfo(string ProcessName, string User)
{
    public static ProcessInfo FromPid(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var name = process.ProcessName;
            var user = ProcessUserResolver.ResolveUser(process);
            return new ProcessInfo(name, user);
        }
        catch
        {
            return new ProcessInfo("unknown", "unknown");
        }
    }
}

internal static class ProcessUserResolver
{
    public static string ResolveUser(Process process)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId={process.Id}");
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                var args = new string[2];
                var returnValue = Convert.ToInt32(obj.InvokeMethod("GetOwner", args));
                if (returnValue == 0)
                {
                    return $"{args[1]}\\{args[0]}";
                }
            }
        }
        catch
        {
        }

        return "unknown";
    }
}

internal sealed class DnsCache
{
    private readonly ConcurrentDictionary<IPAddress, List<string>> _map = new();

    public void TrackQuery(string queryName)
    {
    }

    public void TrackResponse(IPAddress ip, string name)
    {
        _map.AddOrUpdate(ip,
            _ => new List<string> { name },
            (_, existing) =>
            {
                if (!existing.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    existing.Add(name);
                }

                return existing;
            });
    }

    public IReadOnlyList<string> Resolve(IPAddress ip)
    {
        if (_map.TryGetValue(ip, out var names))
        {
            return names;
        }

        return Array.Empty<string>();
    }
}

internal sealed class ServiceResolver
{
    public IReadOnlyList<string> ResolveServices(int pid)
    {
        var services = new List<string>();
        try
        {
            foreach (var service in ServiceController.GetServices())
            {
                try
                {
                    if (service.Status == ServiceControllerStatus.Running &&
                        ServicePidResolver.TryGetServicePid(service.ServiceName, out var servicePid) &&
                        servicePid == pid)
                    {
                        services.Add(service.ServiceName);
                    }
                }
                catch
                {
                }
            }
        }
        catch
        {
        }

        return services;
    }
}

internal static class ServicePidResolver
{
    public static bool TryGetServicePid(string serviceName, out int pid)
    {
        pid = 0;
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"queryex {serviceName}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(1000);
            var match = System.Text.RegularExpressions.Regex.Match(output, @"PID\s*:\s*(\d+)");
            if (match.Success && int.TryParse(match.Groups[1].Value, out var parsed))
            {
                pid = parsed;
                return true;
            }
        }
        catch
        {
        }

        return false;
    }
}

internal sealed class TaskSchedulerResolver
{
    private DateTime _lastRefresh = DateTime.MinValue;
    private List<TaskInfo> _cached = new();

    public IReadOnlyList<string> GetTasksNear(DateTime timestampUtc)
    {
        if ((DateTime.UtcNow - _lastRefresh) > TimeSpan.FromMinutes(2))
        {
            _cached = LoadTasks();
            _lastRefresh = DateTime.UtcNow;
        }

        var window = TimeSpan.FromMinutes(5);
        var matches = _cached
            .Where(task => task.LastRunUtc.HasValue &&
                           Math.Abs((task.LastRunUtc.Value - timestampUtc).TotalMinutes) <= window.TotalMinutes)
            .Select(task => task.Name)
            .Distinct()
            .ToList();

        return matches;
    }

    private static List<TaskInfo> LoadTasks()
    {
        var tasks = new List<TaskInfo>();
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "schtasks",
                Arguments = "/query /fo LIST /v",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(2000);

            var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string? name = null;
            DateTime? lastRun = null;
            foreach (var line in lines)
            {
                if (line.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase))
                {
                    if (name != null)
                    {
                        tasks.Add(new TaskInfo(name, lastRun));
                    }

                    name = line.Split(':', 2).ElementAtOrDefault(1)?.Trim();
                    lastRun = null;
                }
                else if (line.StartsWith("Last Run Time:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = line.Split(':', 2).ElementAtOrDefault(1)?.Trim();
                    if (DateTime.TryParse(value, out var parsed))
                    {
                        lastRun = DateTime.SpecifyKind(parsed, DateTimeKind.Local).ToUniversalTime();
                    }
                }
            }

            if (name != null)
            {
                tasks.Add(new TaskInfo(name, lastRun));
            }
        }
        catch
        {
        }

        return tasks;
    }
}

internal sealed record TaskInfo(string Name, DateTime? LastRunUtc);

internal static class Classifier
{
    private static readonly HashSet<string> UpdateServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "wuauserv", "UsoSvc", "DoSvc", "WaaSMedicSvc", "BITS"
    };

    private static readonly HashSet<string> DefenderServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "WdNisSvc", "SecurityHealthService"
    };

    private static readonly HashSet<string> StoreServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "InstallService", "ClipSVC", "LicenseManager"
    };

    private static readonly HashSet<string> TimeServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "W32Time"
    };

    public static ClassificationResult Classify(ProcessInfo processInfo, IReadOnlyList<string> services, IReadOnlyList<string> dnsNames)
    {
        var lowerProcess = processInfo.ProcessName.ToLowerInvariant();
        var lowerDns = dnsNames.Select(d => d.ToLowerInvariant()).ToList();

        if (services.Any(s => UpdateServices.Contains(s)) || lowerProcess.Contains("wuauclt"))
        {
            return new ClassificationResult("Windows Update", 0.8);
        }

        if (services.Any(s => DefenderServices.Contains(s)) || lowerProcess.Contains("msmpeng"))
        {
            return new ClassificationResult("Defender", 0.8);
        }

        if (services.Any(s => StoreServices.Contains(s)) || lowerProcess.Contains("wsappx"))
        {
            return new ClassificationResult("Store", 0.7);
        }

        if (services.Any(s => TimeServices.Contains(s)) || lowerDns.Any(d => d.Contains("time.windows.com")))
        {
            return new ClassificationResult("Time Sync", 0.7);
        }

        if (lowerDns.Any(d => d.Contains("windowsupdate") || d.Contains("update.microsoft")))
        {
            return new ClassificationResult("Windows Update", 0.6);
        }

        if (lowerDns.Any(d => d.Contains("telemetry") || d.Contains("data.microsoft")))
        {
            return new ClassificationResult("Telemetry", 0.5);
        }

        return new ClassificationResult("Other", 0.3);
    }
}

internal sealed record ClassificationResult(string Category, double Confidence);

internal static class SummaryReport
{
    public static void Run(string inputPath)
    {
        var byProcess = new Dictionary<string, TrafficAggregate>(StringComparer.OrdinalIgnoreCase);
        var byDestination = new Dictionary<string, TrafficAggregate>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(inputPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var networkEvent = JsonSerializer.Deserialize<NetworkEvent>(line, SerializerOptions.Options);
            if (networkEvent == null)
            {
                continue;
            }

            var processKey = $"{networkEvent.ProcessName} ({networkEvent.Pid})";
            Aggregate(byProcess, processKey, networkEvent.BytesSent, networkEvent.BytesRecv);

            var destKey = $"{networkEvent.RemoteIp}:{networkEvent.RemotePort} ({networkEvent.Protocol})";
            Aggregate(byDestination, destKey, networkEvent.BytesSent, networkEvent.BytesRecv);
        }

        Console.WriteLine("Summary by process:");
        PrintAggregate(byProcess);

        Console.WriteLine("\nTop destinations:");
        PrintAggregate(byDestination);
    }

    private static void Aggregate(Dictionary<string, TrafficAggregate> map, string key, long sent, long recv)
    {
        if (!map.TryGetValue(key, out var agg))
        {
            agg = new TrafficAggregate();
            map[key] = agg;
        }

        agg.Sent += sent;
        agg.Received += recv;
    }

    private static void PrintAggregate(Dictionary<string, TrafficAggregate> map)
    {
        foreach (var item in map.OrderByDescending(kvp => kvp.Value.Total).Take(10))
        {
            Console.WriteLine($"  {item.Key} -> sent {item.Value.Sent} bytes, recv {item.Value.Received} bytes");
        }
    }

    private sealed class TrafficAggregate
    {
        public long Sent { get; set; }
        public long Received { get; set; }
        public long Total => Sent + Received;
    }
}
