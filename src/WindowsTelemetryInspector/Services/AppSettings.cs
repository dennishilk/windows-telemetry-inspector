using System.Text.Json;
using WindowsTelemetryInspector.Infrastructure;

namespace WindowsTelemetryInspector.Services;

public sealed class AppSettings : BindableBase
{
    private bool _includeDns = true;
    private int _refreshIntervalMilliseconds = 250;
    private int _maximumInMemoryEvents = 50_000;
    private bool _autoScroll = true;
    private string _captureDirectory = SettingsStore.DefaultCaptureDirectory;

    public bool IncludeDns
    {
        get => _includeDns;
        set => SetProperty(ref _includeDns, value);
    }

    public int RefreshIntervalMilliseconds
    {
        get => _refreshIntervalMilliseconds;
        set => SetProperty(ref _refreshIntervalMilliseconds, Math.Clamp(value, 100, 2_000));
    }

    public int MaximumInMemoryEvents
    {
        get => _maximumInMemoryEvents;
        set => SetProperty(ref _maximumInMemoryEvents, Math.Clamp(value, 5_000, 200_000));
    }

    public bool AutoScroll
    {
        get => _autoScroll;
        set => SetProperty(ref _autoScroll, value);
    }

    public string CaptureDirectory
    {
        get => _captureDirectory;
        set => SetProperty(ref _captureDirectory, string.IsNullOrWhiteSpace(value) ? SettingsStore.DefaultCaptureDirectory : value);
    }
}

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static string ApplicationDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WindowsTelemetryInspector");

    public static string DefaultCaptureDirectory => Path.Combine(ApplicationDirectory, "Captures");

    public static string SettingsPath => Path.Combine(ApplicationDirectory, "settings.json");

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return new AppSettings();
            }

            var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath), JsonOptions);
            return settings ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(ApplicationDirectory);
        Directory.CreateDirectory(settings.CaptureDirectory);
        var temporaryPath = SettingsPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(settings, JsonOptions));
        File.Move(temporaryPath, SettingsPath, true);
    }
}
