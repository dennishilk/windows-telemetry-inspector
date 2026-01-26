namespace NetworkTransparency.Tests;

public sealed class ClassifierTests
{
    [Theory]
    [InlineData("WUAUSERV", "Windows Update")]
    [InlineData("UsoSvc", "Windows Update")]
    [InlineData("BITS", "Windows Update")]
    [InlineData("WinDefend", "Defender")]
    [InlineData("WdNisSvc", "Defender")]
    [InlineData("SecurityHealthService", "Defender")]
    [InlineData("InstallService", "Store")]
    [InlineData("ClipSVC", "Store")]
    [InlineData("LicenseManager", "Store")]
    [InlineData("W32Time", "Time Sync")]
    public void Classify_UsesServiceNamesCaseInsensitively(string serviceName, string expectedCategory)
    {
        var processInfo = new ProcessInfo("svchost", "SYSTEM");
        var services = new List<string> { serviceName };
        var dnsNames = Array.Empty<string>();

        var result = Classifier.Classify(processInfo, services, dnsNames);

        Assert.Equal(expectedCategory, result.Category);
    }
}
