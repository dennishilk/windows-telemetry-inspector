using NetworkTransparency.Core.Analysis;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Tests;

public sealed class CaptureAnalyzerTests
{
    [Fact]
    public void Summarize_UsesFlowDeltasInsteadOfAddingCumulativeCounters()
    {
        var started = new DateTime(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
        var events = new[]
        {
            Event(started, bytesSent: 100, bytesReceived: 40),
            Event(started.AddSeconds(1), bytesSent: 250, bytesReceived: 80),
            Event(started.AddSeconds(2), bytesSent: 400, bytesReceived: 100)
        };

        var summary = CaptureAnalyzer.Summarize(events);

        Assert.Equal(3, summary.EventCount);
        Assert.Equal(400, summary.BytesSent);
        Assert.Equal(100, summary.BytesReceived);
        Assert.Equal(TimeSpan.FromSeconds(2), summary.Duration);
    }

    [Fact]
    public void Summarize_SeparatesIndependentFlows()
    {
        var timestamp = DateTime.UtcNow;
        var first = Event(timestamp, remoteIp: "20.1.1.1", bytesSent: 100, bytesReceived: 20);
        var second = Event(timestamp.AddSeconds(1), remoteIp: "20.1.1.2", bytesSent: 50, bytesReceived: 10) with
        {
            DnsNames = ["other.example"]
        };

        var summary = CaptureAnalyzer.Summarize([first, second]);

        Assert.Equal(150, summary.BytesSent);
        Assert.Equal(30, summary.BytesReceived);
        Assert.Equal(2, summary.TopRemoteHosts.Count);
    }

    [Fact]
    public void CalculateDeltas_HandlesCounterReset()
    {
        var timestamp = DateTime.UtcNow;
        var result = CaptureAnalyzer.CalculateDeltas([
            Event(timestamp, bytesSent: 500, bytesReceived: 100),
            Event(timestamp.AddSeconds(1), bytesSent: 40, bytesReceived: 5)
        ]);

        Assert.Equal(500, result[0].BytesSent);
        Assert.Equal(40, result[1].BytesSent);
        Assert.Equal(5, result[1].BytesReceived);
    }

    internal static NetworkEvent Event(
        DateTime timestamp,
        string remoteIp = "20.190.128.1",
        long bytesSent = 0,
        long bytesReceived = 0,
        string process = "svchost",
        string category = "Windows Update") => new(
            timestamp,
            1052,
            process,
            "NT AUTHORITY\\SYSTEM",
            ["wuauserv"],
            "10.0.0.15",
            49832,
            remoteIp,
            443,
            "TCP",
            bytesSent,
            bytesReceived,
            ["settings-win.data.microsoft.com"],
            null,
            category,
            0.9,
            [],
            "send");
}
