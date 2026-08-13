using System.Text;
using System.Text.Json;
using NetworkTransparency.Core.Capture;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Persistence;

public static class CaptureJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };
}

public sealed class JsonlEventSink : IEventSink
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private bool _disposed;

    public JsonlEventSink(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A capture path is required.", nameof(path));
        }

        var fullPath = System.IO.Path.GetFullPath(path);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        var stream = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
        Path = fullPath;
    }

    public string Path { get; }

    public void Write(NetworkEvent networkEvent)
    {
        var json = JsonSerializer.Serialize(networkEvent, CaptureJson.Options);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _writer.WriteLine(json);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _writer.Dispose();
        }
    }
}

public static class JsonlCaptureStore
{
    public static CaptureLoadResult Read(string path, int? maximumEvents = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A capture path is required.", nameof(path));
        }

        var fullPath = System.IO.Path.GetFullPath(path);
        var isBounded = maximumEvents is > 0;
        var events = isBounded ? null : new List<NetworkEvent>();
        var retained = isBounded ? new Queue<NetworkEvent>(maximumEvents!.Value) : null;
        var malformed = 0;
        var empty = 0;

        foreach (var line in File.ReadLines(fullPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                empty++;
                continue;
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<NetworkEvent>(line, CaptureJson.Options);
                if (parsed is null || parsed.Pid < 0 || parsed.TimestampUtc == default)
                {
                    malformed++;
                    continue;
                }

                var normalized = Normalize(parsed);
                if (retained is not null)
                {
                    if (retained.Count == maximumEvents!.Value)
                    {
                        retained.Dequeue();
                    }

                    retained.Enqueue(normalized);
                }
                else
                {
                    events!.Add(normalized);
                }
            }
            catch (JsonException)
            {
                malformed++;
            }
        }

        return new CaptureLoadResult(
            retained is null ? events! : retained.ToArray(),
            malformed,
            empty,
            fullPath);
    }

    public static void Write(string path, IEnumerable<NetworkEvent> events)
    {
        using var sink = new JsonlEventSink(path);
        foreach (var networkEvent in events)
        {
            sink.Write(networkEvent);
        }
    }

    private static NetworkEvent Normalize(NetworkEvent networkEvent)
    {
        var services = networkEvent.ServiceNames ?? Array.Empty<string>();
        var dnsNames = networkEvent.DnsNames ?? Array.Empty<string>();
        var tasks = networkEvent.RelatedTasks ?? Array.Empty<string>();
        var processName = string.IsNullOrWhiteSpace(networkEvent.ProcessName) ? "Unknown" : networkEvent.ProcessName;
        var user = string.IsNullOrWhiteSpace(networkEvent.User) ? "Unknown" : networkEvent.User;
        var category = string.IsNullOrWhiteSpace(networkEvent.Classification) ? "Other" : networkEvent.Classification;
        var protocol = string.IsNullOrWhiteSpace(networkEvent.Protocol) ? "Unknown" : networkEvent.Protocol;

        return networkEvent with
        {
            ProcessName = processName,
            User = user,
            ServiceNames = services,
            DnsNames = dnsNames,
            RelatedTasks = tasks,
            Classification = category,
            Protocol = protocol,
            Notes = networkEvent.Notes ?? string.Empty,
            Process = networkEvent.Process ?? (ProcessMetadata.Unknown(networkEvent.Pid) with
            {
                ProcessName = processName,
                User = user
            }),
            Services = networkEvent.Services ?? services.Select(name => new ServiceInfo(name, "Not available", "Unknown")).ToArray(),
            Direction = string.IsNullOrWhiteSpace(networkEvent.Direction) ? "Unknown" : networkEvent.Direction,
            EtwProvider = string.IsNullOrWhiteSpace(networkEvent.EtwProvider) ? "Not available" : networkEvent.EtwProvider,
            TaskCorrelations = networkEvent.TaskCorrelations ?? tasks.Select(task => new TaskCorrelation(
                task,
                task,
                null,
                null,
                "Timing unavailable in legacy capture")).ToArray()
        };
    }
}
