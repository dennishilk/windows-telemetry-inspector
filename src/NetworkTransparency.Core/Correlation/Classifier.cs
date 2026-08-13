using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Correlation;

public static class Classifier
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

    public static ClassificationResult Classify(
        ProcessMetadata process,
        IReadOnlyList<string> services,
        IReadOnlyList<string> dnsNames)
    {
        var processName = process.ProcessName;

        if (services.Any(UpdateServices.Contains) || Contains(processName, "wuauclt", "usoclient", "mousocoreworker"))
        {
            return new ClassificationResult("Windows Update", 0.90, "Known update service or process");
        }

        if (services.Any(DefenderServices.Contains) || Contains(processName, "msmpeng", "nissrv"))
        {
            return new ClassificationResult("Microsoft Defender", 0.90, "Known Microsoft Defender service or process");
        }

        if (services.Any(StoreServices.Contains) || Contains(processName, "wsappx", "winget"))
        {
            return new ClassificationResult("Microsoft Store", 0.82, "Known Microsoft Store service or process");
        }

        if (services.Any(TimeServices.Contains) || dnsNames.Any(IsWindowsTimeHost))
        {
            return new ClassificationResult("Time Sync", 0.85, "Windows time service or known time host");
        }

        if (dnsNames.Any(IsWindowsUpdateHost))
        {
            return new ClassificationResult("Windows Update", 0.65, "DNS-name heuristic");
        }

        if (dnsNames.Any(IsDefenderHost))
        {
            return new ClassificationResult("Microsoft Defender", 0.65, "DNS-name heuristic");
        }

        if (dnsNames.Any(IsTelemetryHost))
        {
            return new ClassificationResult("Telemetry", 0.55, "DNS-name heuristic");
        }

        return new ClassificationResult("Other", 0.35, "No known service, process, or DNS heuristic matched");
    }

    private static bool Contains(string value, params string[] candidates) =>
        candidates.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    private static bool IsWindowsUpdateHost(string host) =>
        HostHasLabel(host, "windowsupdate") ||
        HostEqualsOrSubdomain(host, "update.microsoft.com") ||
        HostEqualsOrSubdomain(host, "delivery.mp.microsoft.com");

    private static bool IsDefenderHost(string host) =>
        HostEqualsOrSubdomain(host, "wdcp.microsoft.com") ||
        HostEqualsOrSubdomain(host, "wd.microsoft.com");

    private static bool IsTelemetryHost(string host) =>
        HostHasLabel(host, "telemetry") ||
        HostEqualsOrSubdomain(host, "data.microsoft.com") ||
        HostEqualsOrSubdomain(host, "vortex.data.microsoft.com");

    private static bool IsWindowsTimeHost(string host) =>
        HostEqualsOrSubdomain(host, "time.windows.com");

    private static bool HostHasLabel(string host, string label) =>
        host.TrimEnd('.').Split('.').Any(part => part.Equals(label, StringComparison.OrdinalIgnoreCase));

    private static bool HostEqualsOrSubdomain(string host, string domain)
    {
        var normalized = host.TrimEnd('.');
        return normalized.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith($".{domain}", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record ClassificationResult(string Category, double Confidence, string Reason);
