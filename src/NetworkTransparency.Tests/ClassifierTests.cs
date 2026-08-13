using NetworkTransparency.Core.Correlation;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Tests;

public sealed class ClassifierTests
{
    [Theory]
    [InlineData("WUAUSERV", "Windows Update")]
    [InlineData("UsoSvc", "Windows Update")]
    [InlineData("BITS", "Windows Update")]
    [InlineData("WinDefend", "Microsoft Defender")]
    [InlineData("WdNisSvc", "Microsoft Defender")]
    [InlineData("SecurityHealthService", "Microsoft Defender")]
    [InlineData("InstallService", "Microsoft Store")]
    [InlineData("ClipSVC", "Microsoft Store")]
    [InlineData("LicenseManager", "Microsoft Store")]
    [InlineData("W32Time", "Time Sync")]
    public void Classify_UsesServiceNamesCaseInsensitively(string serviceName, string expectedCategory)
    {
        var result = Classifier.Classify(Process("svchost"), [serviceName], []);

        Assert.Equal(expectedCategory, result.Category);
        Assert.True(result.Confidence >= 0.8);
    }

    [Theory]
    [InlineData("settings-win.data.microsoft.com", "Telemetry")]
    [InlineData("vortex.data.microsoft.com", "Telemetry")]
    [InlineData("download.windowsupdate.com", "Windows Update")]
    [InlineData("time.windows.com", "Time Sync")]
    [InlineData("wdcp.microsoft.com", "Microsoft Defender")]
    public void Classify_UsesDnsHeuristics(string dnsName, string expectedCategory)
    {
        var result = Classifier.Classify(Process("svchost"), [], [dnsName]);

        Assert.Equal(expectedCategory, result.Category);
        Assert.InRange(result.Confidence, 0.5, 0.9);
    }

    [Fact]
    public void Classify_PrefersKnownServiceOverConflictingDnsHeuristic()
    {
        var result = Classifier.Classify(Process("svchost"), ["WinDefend"], ["download.windowsupdate.com"]);

        Assert.Equal("Microsoft Defender", result.Category);
        Assert.Equal(0.90, result.Confidence);
    }

    [Fact]
    public void Classify_ReturnsOtherWhenNothingMatches()
    {
        var result = Classifier.Classify(Process("custom-agent"), [], ["example.org"]);

        Assert.Equal("Other", result.Category);
        Assert.Equal(0.35, result.Confidence);
    }

    private static ProcessMetadata Process(string name) => ProcessMetadata.Unknown(100) with { ProcessName = name };
}
