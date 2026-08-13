using NetworkTransparency.Core.Analysis;

namespace NetworkTransparency.Tests;

public sealed class CaptureFilterTests
{
    private readonly DateTime _timestamp = new(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Matches_SearchesAcrossProcessHostServiceAndEndpointFields()
    {
        var networkEvent = CaptureAnalyzerTests.Event(_timestamp);

        Assert.True(CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(SearchText: "svchost")));
        Assert.True(CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(SearchText: "settings-win")));
        Assert.True(CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(SearchText: "wuauserv")));
        Assert.True(CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(SearchText: "20.190.128.1")));
        Assert.False(CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(SearchText: "does-not-exist")));
    }

    [Fact]
    public void Matches_CombinesSpecificFiltersWithAndSemantics()
    {
        var networkEvent = CaptureAnalyzerTests.Event(_timestamp);
        var matching = new CaptureFilterCriteria(
            Process: "svchost",
            Protocol: "TCP",
            Category: "Windows Update",
            Remote: "data.microsoft",
            Pid: 1052,
            Service: "WUAUSERV",
            DnsName: "settings-win");

        Assert.True(CaptureFilter.Matches(networkEvent, matching));
        Assert.False(CaptureFilter.Matches(networkEvent, matching with { Pid = 9999 }));
    }
}
