using System.Collections.Concurrent;
using System.Management;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Correlation;

internal sealed class ServiceResolver
{
    private readonly ConcurrentDictionary<int, CacheEntry> _cache = new();
    private readonly TimeSpan _cacheDuration = TimeSpan.FromSeconds(30);

    public IReadOnlyList<ServiceInfo> Resolve(int pid)
    {
        if (pid <= 0 || !OperatingSystem.IsWindows())
        {
            return Array.Empty<ServiceInfo>();
        }

        if (_cache.TryGetValue(pid, out var cached) && DateTime.UtcNow - cached.CreatedUtc < _cacheDuration)
        {
            return cached.Services;
        }

        var resolved = ResolveCore(pid);
        _cache[pid] = new CacheEntry(DateTime.UtcNow, resolved);

        if (_cache.Count > 512)
        {
            foreach (var item in _cache.Where(pair => DateTime.UtcNow - pair.Value.CreatedUtc > _cacheDuration))
            {
                _cache.TryRemove(item.Key, out _);
            }
        }

        return resolved;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IReadOnlyList<ServiceInfo> ResolveCore(int pid)
    {
        var services = new List<ServiceInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, DisplayName, State FROM Win32_Service WHERE ProcessId={pid}");
            using var results = searcher.Get();
            foreach (ManagementObject item in results)
            {
                var name = item["Name"]?.ToString();
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                services.Add(new ServiceInfo(
                    name,
                    ValueOr(item["DisplayName"]?.ToString(), "Not available"),
                    ValueOr(item["State"]?.ToString(), "Unknown")));
            }
        }
        catch
        {
        }

        return services.OrderBy(service => service.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string ValueOr(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private sealed record CacheEntry(DateTime CreatedUtc, IReadOnlyList<ServiceInfo> Services);
}
