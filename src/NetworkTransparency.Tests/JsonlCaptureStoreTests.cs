using System.Text.Json;
using NetworkTransparency.Core.Persistence;

namespace NetworkTransparency.Tests;

public sealed class JsonlCaptureStoreTests
{
    [Fact]
    public void Read_PreservesLegacySchemaAndSkipsMalformedLines()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wti-{Guid.NewGuid():N}.jsonl");
        try
        {
            var timestamp = new DateTime(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
            var legacy = JsonSerializer.Serialize(new
            {
                timestampUtc = timestamp,
                pid = 1052,
                processName = "svchost",
                user = "NT AUTHORITY\\SYSTEM",
                serviceNames = new[] { "wuauserv" },
                localIp = "10.0.0.15",
                localPort = 49832,
                remoteIp = "20.190.128.1",
                remotePort = 443,
                protocol = "TCP",
                bytesSent = 100,
                bytesRecv = 40,
                dnsNames = new[] { "settings-win.data.microsoft.com" },
                sniHost = (string?)null,
                classification = "Windows Update",
                confidence = 0.9,
                relatedTasks = new[] { "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan" },
                notes = "send"
            }, CaptureJson.Options);
            File.WriteAllLines(path, [legacy, "{not valid json", ""]);

            var result = JsonlCaptureStore.Read(path);

            Assert.Single(result.Events);
            Assert.Equal(1, result.MalformedLineCount);
            Assert.Equal(1, result.EmptyLineCount);
            Assert.Equal("svchost", result.Events[0].ProcessName);
            Assert.Null(result.Events[0].CorrelatedTasks[0].LastRunUtc);
            Assert.Equal("Not available", result.Events[0].CorrelatedTasks[0].DistanceDisplay);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void WriteAndRead_RoundTripsExtendedEventMetadata()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wti-{Guid.NewGuid():N}.jsonl");
        try
        {
            var original = CaptureAnalyzerTests.Event(DateTime.UtcNow);
            JsonlCaptureStore.Write(path, [original]);

            var loaded = JsonlCaptureStore.Read(path);

            Assert.Single(loaded.Events);
            Assert.Equal(original.RemoteIp, loaded.Events[0].RemoteIp);
            Assert.Equal(original.Classification, loaded.Events[0].Classification);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Read_BoundsTheRetainedEventCount()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wti-{Guid.NewGuid():N}.jsonl");
        try
        {
            JsonlCaptureStore.Write(path, Enumerable.Range(0, 5)
                .Select(index => CaptureAnalyzerTests.Event(DateTime.UtcNow.AddSeconds(index), bytesSent: index)));

            var loaded = JsonlCaptureStore.Read(path, maximumEvents: 3);

            Assert.Equal(3, loaded.Events.Count);
            Assert.Equal(2, loaded.Events[0].BytesSent);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
