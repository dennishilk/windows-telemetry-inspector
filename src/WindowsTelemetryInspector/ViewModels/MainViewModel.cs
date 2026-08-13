using System.Collections.ObjectModel;
using System.ComponentModel;
using NetworkTransparency.Core.Models;
using WindowsTelemetryInspector.Infrastructure;
using WindowsTelemetryInspector.Services;

namespace WindowsTelemetryInspector.ViewModels;

public sealed class MainViewModel : BindableBase, IDisposable
{
    private readonly IDialogService _dialogs;
    private NavigationItemViewModel? _selectedNavigation;

    public MainViewModel()
    {
        var settingsStore = new SettingsStore();
        var settings = settingsStore.Load();
        _dialogs = new DialogService();
        Workspace = new CaptureWorkspace(settings, settingsStore, _dialogs);

        LiveTraffic = new LiveTrafficViewModel(Workspace);
        Processes = new ProcessesViewModel(Workspace);
        Services = new ServicesViewModel(Workspace);
        Dns = new DnsViewModel(Workspace);
        Timeline = new TimelineViewModel(Workspace);
        Captures = new CapturesViewModel(Workspace);
        Summary = new SummaryViewModel(Workspace);
        Settings = new SettingsViewModel(Workspace);
        About = new AboutViewModel(Workspace);

        Navigation = new ObservableCollection<NavigationItemViewModel>
        {
            new("⌁", "Live Traffic", LiveTraffic),
            new("▦", "Processes", Processes),
            new("⚙", "Services", Services),
            new("◎", "DNS Lookups", Dns),
            new("◷", "Timeline", Timeline),
            new("▣", "Captures", Captures),
            new("◔", "Summary", Summary, hasCounter: false),
            new("⚙", "Settings", Settings, dividerBefore: true, hasCounter: false),
            new("ⓘ", "About", About, hasCounter: false)
        };
        SelectedNavigation = Navigation[0];

        StartCaptureCommand = new AsyncRelayCommand(StartCaptureAsync, () => !Workspace.IsCapturing);
        StopCaptureCommand = new AsyncRelayCommand(Workspace.StopCaptureAsync, () => Workspace.IsCapturing);
        ToggleRecordingCommand = new AsyncRelayCommand(ToggleRecordingAsync, () => Workspace.IsCapturing || !Workspace.IsRecording);
        ExportCommand = new AsyncRelayCommand(Workspace.ExportCurrentAsync, () => Workspace.Events.Count > 0);
        OpenCaptureCommand = new AsyncRelayCommand(OpenCaptureAsync);
        ClearCommand = new RelayCommand(ClearWorkspace, () => !Workspace.IsCapturing && Workspace.Events.Count > 0);
        RestartElevatedCommand = new RelayCommand(Workspace.RestartElevated, () => !Workspace.IsElevated);
        OpenFolderCommand = new RelayCommand(Workspace.OpenCaptureFolder);

        Workspace.SnapshotUpdated += OnSnapshotUpdated;
        Workspace.PropertyChanged += OnWorkspacePropertyChanged;
        Workspace.Events.CollectionChanged += (_, _) => RaiseCommandStates();
        UpdateNavigationCounts(Workspace.Snapshot);
    }

    public CaptureWorkspace Workspace { get; }
    public LiveTrafficViewModel LiveTraffic { get; }
    public ProcessesViewModel Processes { get; }
    public ServicesViewModel Services { get; }
    public DnsViewModel Dns { get; }
    public TimelineViewModel Timeline { get; }
    public CapturesViewModel Captures { get; }
    public SummaryViewModel Summary { get; }
    public SettingsViewModel Settings { get; }
    public AboutViewModel About { get; }
    public ObservableCollection<NavigationItemViewModel> Navigation { get; }
    public AsyncRelayCommand StartCaptureCommand { get; }
    public AsyncRelayCommand StopCaptureCommand { get; }
    public AsyncRelayCommand ToggleRecordingCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public AsyncRelayCommand OpenCaptureCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand RestartElevatedCommand { get; }
    public RelayCommand OpenFolderCommand { get; }

    public NavigationItemViewModel? SelectedNavigation
    {
        get => _selectedNavigation;
        set
        {
            if (SetProperty(ref _selectedNavigation, value) && value is not null)
            {
                value.Page.Refresh(Workspace.Snapshot);
                OnPropertyChanged(nameof(CurrentPage));
            }
        }
    }

    public object? CurrentPage => SelectedNavigation?.Page;

    public string RecordButtonText => Workspace.IsRecording ? "Stop Recording" : "Record Capture";

    private async Task StartCaptureAsync()
    {
        if (Workspace.Events.Count > 0 && !_dialogs.Confirm(
                "Start a new capture?",
                "Starting a new capture clears the current in-memory workspace. Export it first if you want to keep it.\n\nContinue?"))
        {
            return;
        }

        await Workspace.StartCaptureAsync(clearExisting: true);
    }

    private async Task ToggleRecordingAsync()
    {
        if (Workspace.IsRecording)
        {
            Workspace.StopRecording();
        }
        else
        {
            await Workspace.StartRecordingAsync();
        }

        OnPropertyChanged(nameof(RecordButtonText));
        RaiseCommandStates();
    }

    private async Task OpenCaptureAsync()
    {
        if (Workspace.IsCapturing && !_dialogs.Confirm(
                "Stop the active capture?",
                "Opening a saved capture stops the current live capture. Continue?"))
        {
            return;
        }

        await Workspace.OpenCaptureAsync();
    }

    private void ClearWorkspace()
    {
        if (!_dialogs.Confirm("Clear the workspace?", "Remove all currently loaded events from memory? Capture files on disk are not deleted."))
        {
            return;
        }

        Workspace.ClearWorkspace();
    }

    private void OnSnapshotUpdated(object? sender, EventArgs e)
    {
        var snapshot = Workspace.Snapshot;
        UpdateNavigationCounts(snapshot);
        SelectedNavigation?.Page.Refresh(snapshot);
        RaiseCommandStates();
    }

    private void OnWorkspacePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(CaptureWorkspace.IsCapturing) or
            nameof(CaptureWorkspace.IsRecording) or
            nameof(CaptureWorkspace.IsElevated))
        {
            OnPropertyChanged(nameof(RecordButtonText));
            RaiseCommandStates();
        }

        if (e.PropertyName == nameof(CaptureWorkspace.DisplayEventCount))
        {
            Navigation[0].Count = Workspace.DisplayEventCount;
            Navigation[4].Count = Workspace.DisplayEventCount;
        }
    }

    private void UpdateNavigationCounts(IReadOnlyList<NetworkEvent> snapshot)
    {
        Navigation[0].Count = Workspace.DisplayEventCount;
        Navigation[1].Count = snapshot.Select(item => item.Pid).Distinct().LongCount();
        Navigation[2].Count = snapshot.SelectMany(item => item.ServiceNames).Distinct(StringComparer.OrdinalIgnoreCase).LongCount();
        Navigation[3].Count = Workspace.DnsObservations.Count;
        Navigation[4].Count = Workspace.DisplayEventCount;
        try
        {
            Navigation[5].Count = Directory.Exists(Workspace.Settings.CaptureDirectory)
                ? Directory.EnumerateFiles(Workspace.Settings.CaptureDirectory, "*.jsonl").LongCount()
                : 0;
        }
        catch
        {
            Navigation[5].Count = 0;
        }
    }

    private void RaiseCommandStates()
    {
        StartCaptureCommand.RaiseCanExecuteChanged();
        StopCaptureCommand.RaiseCanExecuteChanged();
        ToggleRecordingCommand.RaiseCanExecuteChanged();
        ExportCommand.RaiseCanExecuteChanged();
        ClearCommand.RaiseCanExecuteChanged();
        RestartElevatedCommand.RaiseCanExecuteChanged();
    }

    public void Dispose()
    {
        Workspace.Dispose();
    }
}

public sealed class NavigationItemViewModel : BindableBase
{
    private long _count;

    public NavigationItemViewModel(
        string glyph,
        string name,
        IInspectorPage page,
        bool dividerBefore = false,
        bool hasCounter = true)
    {
        Glyph = glyph;
        Name = name;
        Page = page;
        DividerBefore = dividerBefore;
        HasCounter = hasCounter;
    }

    public string Glyph { get; }
    public string Name { get; }
    public IInspectorPage Page { get; }
    public bool DividerBefore { get; }
    public bool HasCounter { get; }

    public long Count
    {
        get => _count;
        set => SetProperty(ref _count, value);
    }
}
