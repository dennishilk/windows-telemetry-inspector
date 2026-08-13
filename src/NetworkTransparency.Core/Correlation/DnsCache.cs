using System.Collections.Concurrent;
using System.Net;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Correlation;

internal sealed class DnsCache
{
    private readonly ConcurrentDictionary<IPAddress, ConcurrentDictionary<string, DateTime>> _responses = new();
    private readonly ConcurrentDictionary<string, DateTime> _queries = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _retention;

    public DnsCache(TimeSpan? retention = null)
    {
        _retention = retention ?? TimeSpan.FromMinutes(30);
    }

    public void TrackQuery(string queryName, DateTime timestampUtc)
    {
        _queries[Normalize(queryName)] = timestampUtc;
        Prune(timestampUtc);
    }

    public void TrackResponse(IPAddress ip, string name, DateTime timestampUtc)
    {
        var names = _responses.GetOrAdd(ip, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
        names[Normalize(name)] = timestampUtc;
        _queries[Normalize(name)] = timestampUtc;
        Prune(timestampUtc);
    }

    public DnsResolution Resolve(IPAddress ip, DateTime timestampUtc)
    {
        if (!_responses.TryGetValue(ip, out var names))
        {
            return new DnsResolution(Array.Empty<string>(), DnsCorrelationState.NotResolved);
        }

        var active = names
            .Where(pair => timestampUtc - pair.Value <= _retention)
            .OrderByDescending(pair => pair.Value)
            .ToArray();

        return active.Length == 0
            ? new DnsResolution(Array.Empty<string>(), DnsCorrelationState.NotResolved)
            : new DnsResolution(
                active.Select(pair => pair.Key).ToArray(),
                timestampUtc - active[0].Value <= TimeSpan.FromSeconds(10)
                    ? DnsCorrelationState.CorrelatedResponse
                    : DnsCorrelationState.Cached);
    }

    private void Prune(DateTime nowUtc)
    {
        if ((_queries.Count + _responses.Count) % 128 != 0)
        {
            return;
        }

        foreach (var query in _queries.Where(pair => nowUtc - pair.Value > _retention))
        {
            _queries.TryRemove(query.Key, out _);
        }

        foreach (var response in _responses)
        {
            foreach (var name in response.Value.Where(pair => nowUtc - pair.Value > _retention))
            {
                response.Value.TryRemove(name.Key, out _);
            }

            if (response.Value.IsEmpty)
            {
                _responses.TryRemove(response.Key, out _);
            }
        }
    }

    private static string Normalize(string host) => host.Trim().TrimEnd('.');
}

internal sealed record DnsResolution(IReadOnlyList<string> Names, DnsCorrelationState State);
