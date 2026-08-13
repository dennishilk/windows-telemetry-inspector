using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using NetworkTransparency.Core.Analysis;
using NetworkTransparency.Core.Models;
using WindowsTelemetryInspector.Infrastructure;
using WindowsTelemetryInspector.Services;

namespace WindowsTelemetryInspector.ViewModels;

public interface IInspectorPage
{
    void Refresh(IReadOnlyList<NetworkEvent> snapshot);
}

public abstract class InspectorPageViewModel : BindableBase, IInspectorPage
{
    protected InspectorPageViewModel(CaptureWorkspace workspace)
    {
        Workspace = workspace;
    }

    public CaptureWorkspace Workspace { get; }

    public abstract void Refresh(IReadOnlyList<NetworkEvent> snapshot);
}

public sealed class LiveTrafficViewModel : InspectorPageViewModel
{
    private string _searchText = string.Empty;
    private string _selectedProtocol = "All";
    private string _selectedCategory = "All";
    private string _processFilter = string.Empty;
    private string _pidFilter = string.Empty;
    private string _remoteFilter = string.Empty;
    private string _serviceFilter = string.Empty;
    private string _dnsFilter = string.Empty;
    private bool _isFilterPanelOpen;
    private NetworkEvent? _selectedEvent;

    public LiveTrafficViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        EventsView = new ListCollectionView(workspace.Events)
        {
            Filter = FilterEvent
        };
        Protocols = new[] { "All", "TCP", "UDP" };
        Categories = new[]
        {
            "All", "Windows Update", "Microsoft Defender", "Telemetry", "Microsoft Store", "Time Sync", "Other"
        };
        ToggleFiltersCommand = new RelayCommand(() => IsFilterPanelOpen = !IsFilterPanelOpen);
        ClearFiltersCommand = new RelayCommand(ClearFilters);
    }

    public ListCollectionView EventsView { get; }
    public IReadOnlyList<string> Protocols { get; }
    public IReadOnlyList<string> Categories { get; }
    public RelayCommand ToggleFiltersCommand { get; }
    public RelayCommand ClearFiltersCommand { get; }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                EventsView.Refresh();
            }
        }
    }

    public string SelectedProtocol
    {
        get => _selectedProtocol;
        set
        {
            if (SetProperty(ref _selectedProtocol, value))
            {
                EventsView.Refresh();
            }
        }
    }

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
            {
                EventsView.Refresh();
            }
        }
    }

    public string ProcessFilter
    {
        get => _processFilter;
        set => SetAndRefresh(ref _processFilter, value);
    }

    public string PidFilter
    {
        get => _pidFilter;
        set => SetAndRefresh(ref _pidFilter, value);
    }

    public string RemoteFilter
    {
        get => _remoteFilter;
        set => SetAndRefresh(ref _remoteFilter, value);
    }

    public string ServiceFilter
    {
        get => _serviceFilter;
        set => SetAndRefresh(ref _serviceFilter, value);
    }

    public string DnsFilter
    {
        get => _dnsFilter;
        set => SetAndRefresh(ref _dnsFilter, value);
    }

    public bool IsFilterPanelOpen
    {
        get => _isFilterPanelOpen;
        set => SetProperty(ref _isFilterPanelOpen, value);
    }

    public NetworkEvent? SelectedEvent
    {
        get => _selectedEvent;
        set => SetProperty(ref _selectedEvent, value);
    }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot)
    {
        EventsView.Refresh();
    }

    private bool FilterEvent(object item)
    {
        if (item is not NetworkEvent networkEvent)
        {
            return false;
        }

        var pid = int.TryParse(PidFilter, out var parsedPid) ? parsedPid : (int?)null;
        if (!string.IsNullOrWhiteSpace(PidFilter) && !pid.HasValue)
        {
            return false;
        }

        return CaptureFilter.Matches(networkEvent, new CaptureFilterCriteria(
            SearchText,
            ProcessFilter,
            SelectedProtocol,
            SelectedCategory,
            RemoteFilter,
            pid,
            ServiceFilter,
            DnsFilter));
    }

    private void SetAndRefresh(ref string storage, string value, [CallerMemberName] string? propertyName = null)
    {
        if (SetProperty(ref storage, value, propertyName))
        {
            EventsView.Refresh();
        }
    }

    private void ClearFilters()
    {
        _searchText = string.Empty;
        _selectedProtocol = "All";
        _selectedCategory = "All";
        _processFilter = string.Empty;
        _pidFilter = string.Empty;
        _remoteFilter = string.Empty;
        _serviceFilter = string.Empty;
        _dnsFilter = string.Empty;
        OnPropertyChanged(nameof(SearchText));
        OnPropertyChanged(nameof(SelectedProtocol));
        OnPropertyChanged(nameof(SelectedCategory));
        OnPropertyChanged(nameof(ProcessFilter));
        OnPropertyChanged(nameof(PidFilter));
        OnPropertyChanged(nameof(RemoteFilter));
        OnPropertyChanged(nameof(ServiceFilter));
        OnPropertyChanged(nameof(DnsFilter));
        EventsView.Refresh();
    }
}

public sealed class ProcessesViewModel : InspectorPageViewModel
{
    private ProcessAggregateRow? _selectedProcess;

    public ProcessesViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        Rows = new BulkObservableCollection<ProcessAggregateRow>();
    }

    public BulkObservableCollection<ProcessAggregateRow> Rows { get; }

    public ProcessAggregateRow? SelectedProcess
    {
        get => _selectedProcess;
        set => SetProperty(ref _selectedProcess, value);
    }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot) =>
        Rows.ReplaceAll(ProjectionBuilder.Processes(snapshot));
}

public sealed class ServicesViewModel : InspectorPageViewModel
{
    private ServiceAggregateRow? _selectedService;

    public ServicesViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        Rows = new BulkObservableCollection<ServiceAggregateRow>();
    }

    public BulkObservableCollection<ServiceAggregateRow> Rows { get; }

    public ServiceAggregateRow? SelectedService
    {
        get => _selectedService;
        set => SetProperty(ref _selectedService, value);
    }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot) =>
        Rows.ReplaceAll(ProjectionBuilder.Services(snapshot));
}

public sealed class DnsViewModel : InspectorPageViewModel
{
    private string _searchText = string.Empty;

    public DnsViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        ObservationsView = new ListCollectionView(workspace.DnsObservations)
        {
            Filter = FilterObservation
        };
    }

    public ListCollectionView ObservationsView { get; }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                ObservationsView.Refresh();
            }
        }
    }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot) => ObservationsView.Refresh();

    private bool FilterObservation(object item)
    {
        if (item is not DnsObservation observation || string.IsNullOrWhiteSpace(SearchText))
        {
            return item is DnsObservation;
        }

        return observation.QueryName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
               (observation.Address?.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
               observation.Pid.ToString().Contains(SearchText, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class TimelineViewModel : InspectorPageViewModel
{
    public TimelineViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        Rows = new BulkObservableCollection<TimelineBucketRow>();
    }

    public BulkObservableCollection<TimelineBucketRow> Rows { get; }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot) =>
        Rows.ReplaceAll(ProjectionBuilder.Timeline(snapshot));
}

public sealed class CapturesViewModel : InspectorPageViewModel
{
    private CaptureFileRow? _selectedCapture;

    public CapturesViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        Files = new BulkObservableCollection<CaptureFileRow>();
        OpenCaptureCommand = new AsyncRelayCommand(workspace.OpenCaptureAsync);
        OpenFolderCommand = new RelayCommand(workspace.OpenCaptureFolder);
        RefreshCommand = new RelayCommand(() => Refresh(workspace.Snapshot));
        OpenSelectedCaptureCommand = new AsyncRelayCommand(OpenSelectedCaptureAsync, () => SelectedCapture is not null);
    }

    public BulkObservableCollection<CaptureFileRow> Files { get; }
    public AsyncRelayCommand OpenCaptureCommand { get; }
    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public AsyncRelayCommand OpenSelectedCaptureCommand { get; }

    public CaptureFileRow? SelectedCapture
    {
        get => _selectedCapture;
        set
        {
            if (SetProperty(ref _selectedCapture, value))
            {
                OpenSelectedCaptureCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot)
    {
        try
        {
            Directory.CreateDirectory(Workspace.Settings.CaptureDirectory);
            Files.ReplaceAll(new DirectoryInfo(Workspace.Settings.CaptureDirectory)
                .EnumerateFiles("*.jsonl", SearchOption.TopDirectoryOnly)
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .Select(file => new CaptureFileRow(file.Name, file.FullName, file.Length, file.LastWriteTime)));
        }
        catch
        {
            Files.ReplaceAll(Array.Empty<CaptureFileRow>());
        }
    }

    private Task OpenSelectedCaptureAsync() =>
        SelectedCapture is null ? Task.CompletedTask : Workspace.OpenCapturePathAsync(SelectedCapture.FullPath);
}

public sealed class SummaryViewModel : InspectorPageViewModel
{
    public SummaryViewModel(CaptureWorkspace workspace) : base(workspace)
    {
    }

    public CaptureSummary Summary => Workspace.Summary;

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot) => OnPropertyChanged(nameof(Summary));
}

public sealed class SettingsViewModel : InspectorPageViewModel
{
    public SettingsViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        RefreshIntervals = new[] { 100, 250, 500, 1_000, 2_000 };
        MaximumEventCounts = new[] { 10_000, 25_000, 50_000, 100_000, 200_000 };
        SaveCommand = new RelayCommand(workspace.SaveSettings);
        OpenFolderCommand = new RelayCommand(workspace.OpenCaptureFolder);
    }

    public AppSettings Settings => Workspace.Settings;
    public IReadOnlyList<int> RefreshIntervals { get; }
    public IReadOnlyList<int> MaximumEventCounts { get; }
    public RelayCommand SaveCommand { get; }
    public RelayCommand OpenFolderCommand { get; }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot)
    {
    }
}

public sealed class AboutViewModel : InspectorPageViewModel
{
    public AboutViewModel(CaptureWorkspace workspace) : base(workspace)
    {
        var assembly = Assembly.GetExecutingAssembly();
        Version = assembly.GetName().Version?.ToString(3) ?? "development";
        RepositoryUrl = "https://github.com/dennishilk/windows-telemetry-inspector";
        OpenRepositoryCommand = new RelayCommand(OpenRepository);
    }

    public string Version { get; }
    public string RepositoryUrl { get; }
    public RelayCommand OpenRepositoryCommand { get; }

    public override void Refresh(IReadOnlyList<NetworkEvent> snapshot)
    {
    }

    private void OpenRepository()
    {
        try
        {
            Process.Start(new ProcessStartInfo(RepositoryUrl) { UseShellExecute = true });
        }
        catch
        {
        }
    }
}
