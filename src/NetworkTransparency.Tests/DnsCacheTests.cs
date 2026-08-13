using System.Net;
using NetworkTransparency.Core.Correlation;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Tests;

public sealed class DnsCacheTests
{
    private static readonly DateTime Timestamp = new(2026, 8, 13, 10, 0, 0, DateTimeKind.Utc);
    private static readonly IPAddress Address = IPAddress.Parse("20.190.128.1");

    [Fact]
    public void Resolve_LabelsRecentResponseAsBestEffortCorrelation()
    {
        var cache = new DnsCache();
        cache.TrackResponse(Address, "Settings-Win.Data.Microsoft.Com.", Timestamp);

        var result = cache.Resolve(Address, Timestamp.AddSeconds(4));

        Assert.Equal(DnsCorrelationState.CorrelatedResponse, result.State);
        Assert.Equal(["Settings-Win.Data.Microsoft.Com"], result.Names);
    }

    [Fact]
    public void Resolve_LabelsOlderRetainedResponseAsCached()
    {
        var cache = new DnsCache();
        cache.TrackResponse(Address, "settings-win.data.microsoft.com", Timestamp);

        var result = cache.Resolve(Address, Timestamp.AddMinutes(2));

        Assert.Equal(DnsCorrelationState.Cached, result.State);
        Assert.Single(result.Names);
    }

    [Fact]
    public void Resolve_DoesNotReturnExpiredOrUnknownResponses()
    {
        var cache = new DnsCache(TimeSpan.FromMinutes(5));
        cache.TrackResponse(Address, "settings-win.data.microsoft.com", Timestamp);

        var expired = cache.Resolve(Address, Timestamp.AddMinutes(6));
        var unknown = cache.Resolve(IPAddress.Parse("203.0.113.8"), Timestamp);

        Assert.Equal(DnsCorrelationState.NotResolved, expired.State);
        Assert.Empty(expired.Names);
        Assert.Equal(DnsCorrelationState.NotResolved, unknown.State);
    }
}
