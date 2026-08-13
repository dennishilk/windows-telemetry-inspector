using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Analysis;

public sealed record CaptureFilterCriteria(
    string? SearchText = null,
    string? Process = null,
    string? Protocol = null,
    string? Category = null,
    string? Remote = null,
    int? Pid = null,
    string? Service = null,
    string? DnsName = null)
{
    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(SearchText) &&
        string.IsNullOrWhiteSpace(Process) &&
        string.IsNullOrWhiteSpace(Protocol) &&
        string.IsNullOrWhiteSpace(Category) &&
        string.IsNullOrWhiteSpace(Remote) &&
        !Pid.HasValue &&
        string.IsNullOrWhiteSpace(Service) &&
        string.IsNullOrWhiteSpace(DnsName);
}

public static class CaptureFilter
{
    public static bool Matches(NetworkEvent networkEvent, CaptureFilterCriteria criteria)
    {
        if (criteria.Pid.HasValue && networkEvent.Pid != criteria.Pid.Value)
        {
            return false;
        }

        if (!Contains(networkEvent.ProcessName, criteria.Process) ||
            !EqualsWhenSpecified(networkEvent.Protocol, criteria.Protocol) ||
            !EqualsWhenSpecified(networkEvent.Classification, criteria.Category))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(criteria.Remote) &&
            !Contains(networkEvent.RemoteIp, criteria.Remote) &&
            !networkEvent.DnsNames.Any(name => Contains(name, criteria.Remote)))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(criteria.Service) &&
            !networkEvent.ServiceNames.Any(name => Contains(name, criteria.Service)))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(criteria.DnsName) &&
            !networkEvent.DnsNames.Any(name => Contains(name, criteria.DnsName)))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(criteria.SearchText))
        {
            return true;
        }

        var search = criteria.SearchText;
        return Contains(networkEvent.ProcessName, search) ||
               Contains(networkEvent.Pid.ToString(), search) ||
               Contains(networkEvent.Protocol, search) ||
               Contains(networkEvent.LocalEndpoint, search) ||
               Contains(networkEvent.RemoteEndpoint, search) ||
               Contains(networkEvent.Classification, search) ||
               networkEvent.DnsNames.Any(name => Contains(name, search)) ||
               networkEvent.ServiceNames.Any(name => Contains(name, search)) ||
               networkEvent.RelatedTasks.Any(name => Contains(name, search));
    }

    private static bool Contains(string? value, string? query) =>
        string.IsNullOrWhiteSpace(query) ||
        (!string.IsNullOrWhiteSpace(value) && value.Contains(query, StringComparison.OrdinalIgnoreCase));

    private static bool EqualsWhenSpecified(string? value, string? expected) =>
        string.IsNullOrWhiteSpace(expected) || expected.Equals("All", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
}
