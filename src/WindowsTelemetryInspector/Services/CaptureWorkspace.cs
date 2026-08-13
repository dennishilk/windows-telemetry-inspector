using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using NetworkTransparency.Core.Analysis;
using NetworkTransparency.Core.Capture;
using NetworkTransparency.Core.Correlation;
using NetworkTransparency.Core.Models;
using NetworkTransparency.Core.Persistence;
using WindowsTelemetryInspector.Infrastructure;

namespace WindowsTelemetryInspector.Services;

public sealed class CaptureWorkspace : BindableBase, IDisposable
{
    private readonly AppSettings _settings;
    private readonly SettingsStore _settingsStore;
    private readonly IDialogService _dialogs;
    private readonly EtwCaptureSession _captureSession = new();
    private readonly ConcurrentQueue<NetworkEvent> _pendingEvents = new();
    private readonly ConcurrentQueue<DnsObservation> _pendingDns = new();
    private readonly ConcurrentQueue<string> _pendingErrors = new();
    private readonly Dictionary<string, FlowSnapshot> _flowSnapshots = new(StringComparer.Ordinal);
    private readonly object _metricsGate = new();
    private readonly object _recordingGate = new();
    private readonly DispatcherTimer _uiTimer;
    private JsonlEventSink? _recordingSink;
    private DateTime? _captureStartedUtc;
    private TimeSpan _completedRuntime;
    private DateTime _lastSummaryRequestUtc = DateTime.MinValue;
    private bool _summaryRefreshing;
    private bool _snapshotDirty;
    private long _sessionEvents;
    private long _sessionBytesSent;
    private long _sessionBytesReceived;
    private long _droppedUiEvents;
    private int _pendingEventCount;
    private int _pendingDnsCount;
    private bool _isCapturing;
    private bool _isRecording;
    private bool _isElevated;
    private bool _hasError;
    private bool _kernelProviderActive;
    private bool _dnsProviderActive;
    private string _captureStateLabel = "CAPTURE IDLE";
    private string _statusMessage = "Ready to begin passive observation";
    private string _runtimeText = "00:00:00";
    private long _displayEventCount;
    private long _displayBytesSent;
    private long _displayBytesReceived;
    private long _displayDroppedEvents;
    private string _currentCapturePath = "No capture file selected";
    private CaptureSummary _summary = CaptureAnalyzer.Summarize(Array.Empty<NetworkEvent>());
    private IReadOnlyList<NetworkEvent> _snapshot = Array.Empty<NetworkEvent>();

    public CaptureWorkspace(AppSettings settings, SettingsStore settingsStore, IDialogService dialogs)
    {
        _settings = settings;
        _settingsStore = settingsStore;
        _dialogs = dialogs;
        _isElevated = ElevationStatus.IsElevated();

        Events = new BulkObservableCollection<NetworkEvent>();
        DnsObservations = new ObservableCollection<DnsObservation>();

        _captureSession.EventReceived += OnEventReceived;
        _captureSession.DnsObserved += (sender, observation) =>
        {
            _ = sender;
            var pendingCount = Interlocked.Increment(ref _pendingDnsCount);
            _pendingDns.Enqueue(observation);
            while (pendingCount > 20_000 && _pendingDns.TryDequeue(out _))
            {
                pendingCount = Interlocked.Decrement(ref _pendingDnsCount);
            }
        };
        _captureSession.StatusChanged += OnCaptureStatusChanged;

        _uiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMilliseconds)
        };
        _uiTimer.Tick += OnUiTick;
        _uiTimer.Start();
    }

    public BulkObservableCollection<NetworkEvent> Events { get; }
    public ObservableCollection<DnsObservation> DnsObservations { get; }
    public AppSettings Settings => _settings;

    public IReadOnlyList<NetworkEvent> Snapshot
    {
        get => _snapshot;
        private set => SetProperty(ref _snapshot, value);
    }

    public CaptureSummary Summary
    {
        get => _summary;
        private set => SetProperty(ref _summary, value);
    }

    public bool IsCapturing
    {
        get => _isCapturing;
        private set => SetProperty(ref _isCapturing, value);
    }

    public bool IsRecording
    {
        get => _isRecording;
        private set => SetProperty(ref _isRecording, value);
    }

    public bool IsElevated
    {
        get => _isElevated;
        private set => SetProperty(ref _isElevated, value);
    }

    public bool HasError
    {
        get => _hasError;
        private set => SetProperty(ref _hasError, value);
    }

    public bool KernelProviderActive
    {
        get => _kernelProviderActive;
        private set => SetProperty(ref _kernelProviderActive, value);
    }

    public bool DnsProviderActive
    {
        get => _dnsProviderActive;
        private set => SetProperty(ref _dnsProviderActive, value);
    }

    public string CaptureStateLabel
    {
        get => _captureStateLabel;
        private set => SetProperty(ref _captureStateLabel, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public string RuntimeText
    {
        get => _runtimeText;
        private set => SetProperty(ref _runtimeText, value);
    }

    public long DisplayEventCount
    {
        get => _displayEventCount;
        private set => SetProperty(ref _displayEventCount, value);
    }

    public long DisplayBytesSent
    {
        get => _displayBytesSent;
        private set => SetProperty(ref _displayBytesSent, value);
    }

    public long DisplayBytesReceived
    {
        get => _displayBytesReceived;
        private set => SetProperty(ref _displayBytesReceived, value);
    }

    public long DisplayDroppedEvents
    {
        get => _displayDroppedEvents;
        private set => SetProperty(ref _displayDroppedEvents, value);
    }

    public string CurrentCapturePath
    {
        get => _currentCapturePath;
        private set => SetProperty(ref _currentCapturePath, value);
    }

    public event EventHandler? SnapshotUpdated;
    public event EventHandler<NetworkEvent>? EventsAppended;

    public async Task<bool> StartCaptureAsync(bool clearExisting = true)
    {
        if (IsCapturing)
        {
            return true;
        }

        if (clearExisting)
        {
            ResetWorkspace();
        }

        HasError = false;
        CaptureStateLabel = "CAPTURE STARTING";
        StatusMessage = "Requesting Windows ETW network providers…";
        _captureStartedUtc = DateTime.UtcNow;
        _completedRuntime = TimeSpan.Zero;

        try
        {
            await _captureSession.StartAsync(new CaptureOptions(_settings.IncludeDns));
            IsCapturing = true;
            CaptureStateLabel = "CAPTURE ACTIVE";
            StatusMessage = "Passive observation — no blocking / no MITM";
            return true;
        }
        catch (CapturePermissionException)
        {
            HasError = true;
            CaptureStateLabel = "ADMIN REQUIRED";
            StatusMessage = "Full ETW capture requires Administrator privileges. Use “Restart as administrator” when ready.";
            IsCapturing = false;
            return false;
        }
        catch (Exception error)
        {
            HasError = true;
            CaptureStateLabel = "CAPTURE ERROR";
            StatusMessage = error.Message;
            IsCapturing = false;
            return false;
        }
    }

    public async Task StopCaptureAsync()
    {
        if (!IsCapturing && _captureSession.State == CaptureState.Idle)
        {
            StopRecording();
            return;
        }

        CaptureStateLabel = "CAPTURE STOPPING";
        await _captureSession.StopAsync();
        if (_captureStartedUtc.HasValue)
        {
            _completedRuntime = DateTime.UtcNow - _captureStartedUtc.Value;
        }

        IsCapturing = false;
        KernelProviderActive = false;
        DnsProviderActive = false;
        StopRecording();
        DisplayDroppedEvents = _captureSession.DroppedEventCount + Interlocked.Read(ref _droppedUiEvents);
        CaptureStateLabel = DisplayDroppedEvents > 0 ? "CAPTURE STOPPED · DROPS" : "CAPTURE STOPPED";
        if (DisplayDroppedEvents > 0)
        {
            HasError = true;
            StatusMessage = $"Capture stopped — {DisplayDroppedEvents:N0} event(s) omitted after bounded buffers filled";
        }
        else if (!HasError)
        {
            StatusMessage = $"Capture stopped — {DisplayEventCount:N0} events retained";
        }
    }

    public async Task StartRecordingAsync()
    {
        if (IsRecording)
        {
            return;
        }

        var suggested = $"capture-{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.jsonl";
        var path = _dialogs.ChooseSaveCapture(suggested, _settings.CaptureDirectory);
        if (path is null)
        {
            return;
        }

        JsonlEventSink sink;
        try
        {
            sink = new JsonlEventSink(path);
        }
        catch (Exception error)
        {
            _dialogs.ShowError("Capture file unavailable", $"The capture file could not be created.\n\n{error.Message}");
            return;
        }

        lock (_recordingGate)
        {
            _recordingSink = sink;
        }

        CurrentCapturePath = sink.Path;
        IsRecording = true;

        if (!IsCapturing)
        {
            var started = await StartCaptureAsync(clearExisting: true);
            if (!started)
            {
                StopRecording();
            }
        }
    }

    public void StopRecording()
    {
        JsonlEventSink? sink;
        lock (_recordingGate)
        {
            sink = _recordingSink;
            _recordingSink = null;
        }

        try
        {
            sink?.Dispose();
        }
        catch (Exception error)
        {
            HasError = true;
            StatusMessage = $"Capture file could not be closed cleanly: {error.Message}";
        }

        IsRecording = false;
    }

    public async Task OpenCaptureAsync()
    {
        var path = _dialogs.ChooseOpenCapture();
        if (path is null)
        {
            return;
        }

        await OpenCapturePathAsync(path);
    }

    public async Task OpenCapturePathAsync(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (IsCapturing)
        {
            await StopCaptureAsync();
        }

        CaptureStateLabel = "OPENING CAPTURE";
        StatusMessage = "Reading and validating JSONL…";

        CaptureLoadResult loaded;
        try
        {
            loaded = await Task.Run(() => JsonlCaptureStore.Read(path, _settings.MaximumInMemoryEvents));
        }
        catch (Exception error)
        {
            HasError = true;
            CaptureStateLabel = "OPEN ERROR";
            StatusMessage = error.Message;
            _dialogs.ShowError("Capture could not be opened", error.Message);
            return;
        }

        ResetWorkspace();
        Events.ReplaceAll(loaded.Events);
        DnsObservations.Clear();
        foreach (var observation in BuildDnsObservations(loaded.Events).TakeLast(10_000))
        {
            DnsObservations.Add(observation);
        }

        Snapshot = loaded.Events;
        Summary = await Task.Run(() => CaptureAnalyzer.Summarize(loaded.Events, 50));
        ApplySummaryMetrics(Summary);
        CurrentCapturePath = loaded.Path;
        _completedRuntime = Summary.Duration;
        RuntimeText = FormatRuntime(_completedRuntime);
        CaptureStateLabel = "CAPTURE LOADED";
        HasError = loaded.MalformedLineCount > 0;
        StatusMessage = loaded.MalformedLineCount == 0
            ? $"Loaded {loaded.Events.Count:N0} events from {Path.GetFileName(loaded.Path)}"
            : $"Loaded {loaded.Events.Count:N0} events; skipped {loaded.MalformedLineCount:N0} malformed line(s)";
        SnapshotUpdated?.Invoke(this, EventArgs.Empty);
    }

    public async Task ExportCurrentAsync()
    {
        var snapshot = Events.ToArray();
        if (snapshot.Length == 0)
        {
            _dialogs.ShowInformation("Nothing to export", "Start a capture or open a JSONL capture first.");
            return;
        }

        var suggested = $"capture-export-{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.jsonl";
        var path = _dialogs.ChooseSaveCapture(suggested, _settings.CaptureDirectory);
        if (path is null)
        {
            return;
        }

        try
        {
            await Task.Run(() => JsonlCaptureStore.Write(path, snapshot));
            CurrentCapturePath = Path.GetFullPath(path);
            StatusMessage = $"Exported {snapshot.Length:N0} events to {Path.GetFileName(path)}";
        }
        catch (Exception error)
        {
            HasError = true;
            StatusMessage = $"Export failed: {error.Message}";
            _dialogs.ShowError("Export failed", error.Message);
        }
    }

    public void ClearWorkspace()
    {
        if (IsCapturing)
        {
            return;
        }

        ResetWorkspace();
        CaptureStateLabel = "CAPTURE IDLE";
        StatusMessage = "Workspace cleared";
    }

    public void SaveSettings()
    {
        try
        {
            _settingsStore.Save(_settings);
            _uiTimer.Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMilliseconds);
            StatusMessage = "Settings saved";
        }
        catch (Exception error)
        {
            HasError = true;
            StatusMessage = $"Settings could not be saved: {error.Message}";
            _dialogs.ShowError("Settings could not be saved", error.Message);
        }
    }

    public void OpenCaptureFolder()
    {
        try
        {
            Directory.CreateDirectory(_settings.CaptureDirectory);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{_settings.CaptureDirectory}\"",
                UseShellExecute = true
            });
        }
        catch (Exception error)
        {
            _dialogs.ShowError("Folder could not be opened", error.Message);
        }
    }

    public void RestartElevated()
    {
        if (IsElevated)
        {
            return;
        }

        try
        {
            var executable = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executable))
            {
                throw new InvalidOperationException("The application executable path is unavailable.");
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = true,
                Verb = "runas"
            });
            Application.Current.Shutdown();
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            StatusMessage = "Administrator restart was cancelled";
        }
        catch (Exception error)
        {
            _dialogs.ShowError("Could not restart as administrator", error.Message);
        }
    }

    private void OnEventReceived(object? sender, NetworkEvent networkEvent)
    {
        JsonlEventSink? recordingSink;
        lock (_recordingGate)
        {
            recordingSink = _recordingSink;
        }

        if (recordingSink is not null)
        {
            try
            {
                recordingSink.Write(networkEvent);
            }
            catch (Exception error)
            {
                _pendingErrors.Enqueue($"Recording stopped because the capture file could not be written: {error.Message}");
                lock (_recordingGate)
                {
                    if (ReferenceEquals(_recordingSink, recordingSink))
                    {
                        _recordingSink = null;
                    }
                }

                try
                {
                    recordingSink.Dispose();
                }
                catch
                {
                }
            }
        }

        lock (_metricsGate)
        {
            var key = FlowKey(networkEvent);
            _flowSnapshots.TryGetValue(key, out var previous);
            _sessionBytesSent += Delta(previous.BytesSent, networkEvent.BytesSent);
            _sessionBytesReceived += Delta(previous.BytesReceived, networkEvent.BytesRecv);
            _flowSnapshots[key] = new FlowSnapshot(networkEvent.BytesSent, networkEvent.BytesRecv);
            _sessionEvents++;
        }

        var pendingCount = Interlocked.Increment(ref _pendingEventCount);
        _pendingEvents.Enqueue(networkEvent);
        var maximumPending = Math.Max(10_000, _settings.MaximumInMemoryEvents * 2);
        while (pendingCount > maximumPending && _pendingEvents.TryDequeue(out _))
        {
            pendingCount = Interlocked.Decrement(ref _pendingEventCount);
            Interlocked.Increment(ref _droppedUiEvents);
        }
    }

    private void OnCaptureStatusChanged(object? sender, CaptureStatus status)
    {
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            KernelProviderActive = status.KernelProviderActive;
            DnsProviderActive = status.DnsProviderActive;
            if (status.State == CaptureState.Faulted)
            {
                HasError = true;
                IsCapturing = false;
                StopRecording();
                CaptureStateLabel = "CAPTURE ERROR";
                StatusMessage = status.Message;
            }
        });
    }

    private async void OnUiTick(object? sender, EventArgs e)
    {
        var lastEvent = default(NetworkEvent);
        var appended = 0;
        while (appended < 2_000 && _pendingEvents.TryDequeue(out var networkEvent))
        {
            Interlocked.Decrement(ref _pendingEventCount);
            Events.Add(networkEvent);
            lastEvent = networkEvent;
            appended++;
        }

        while (DnsObservations.Count < 10_000 && _pendingDns.TryDequeue(out var observation))
        {
            Interlocked.Decrement(ref _pendingDnsCount);
            DnsObservations.Add(observation);
        }

        while (_pendingDns.TryDequeue(out var observation))
        {
            Interlocked.Decrement(ref _pendingDnsCount);
            if (DnsObservations.Count >= 10_000)
            {
                DnsObservations.RemoveAt(0);
            }

            DnsObservations.Add(observation);
        }

        if (_pendingErrors.TryDequeue(out var errorMessage))
        {
            HasError = true;
            IsRecording = false;
            StatusMessage = errorMessage;
        }

        var maximum = _settings.MaximumInMemoryEvents;
        while (Events.Count > maximum)
        {
            Events.RemoveAt(0);
        }

        if (appended > 0)
        {
            _snapshotDirty = true;
            EventsAppended?.Invoke(this, lastEvent!);
        }

        lock (_metricsGate)
        {
            DisplayEventCount = _sessionEvents;
            DisplayBytesSent = _sessionBytesSent;
            DisplayBytesReceived = _sessionBytesReceived;
        }

        DisplayDroppedEvents = _captureSession.DroppedEventCount + Interlocked.Read(ref _droppedUiEvents);

        var runtime = IsCapturing && _captureStartedUtc.HasValue
            ? DateTime.UtcNow - _captureStartedUtc.Value
            : _completedRuntime;
        RuntimeText = FormatRuntime(runtime);

        if (_snapshotDirty && !_summaryRefreshing && DateTime.UtcNow - _lastSummaryRequestUtc >= TimeSpan.FromSeconds(1))
        {
            _summaryRefreshing = true;
            _snapshotDirty = false;
            _lastSummaryRequestUtc = DateTime.UtcNow;
            var snapshot = Events.ToArray();
            try
            {
                var summary = await Task.Run(() => CaptureAnalyzer.Summarize(snapshot, 50));
                Snapshot = snapshot;
                Summary = summary;
                SnapshotUpdated?.Invoke(this, EventArgs.Empty);
            }
            finally
            {
                _summaryRefreshing = false;
            }
        }
    }

    private void ResetWorkspace()
    {
        Events.ReplaceAll(Array.Empty<NetworkEvent>());
        DnsObservations.Clear();
        while (_pendingEvents.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _pendingEventCount);
        }

        while (_pendingDns.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _pendingDnsCount);
        }

        Interlocked.Exchange(ref _pendingEventCount, 0);
        Interlocked.Exchange(ref _pendingDnsCount, 0);
        Interlocked.Exchange(ref _droppedUiEvents, 0);

        lock (_metricsGate)
        {
            _flowSnapshots.Clear();
            _sessionEvents = 0;
            _sessionBytesSent = 0;
            _sessionBytesReceived = 0;
        }

        DisplayEventCount = 0;
        DisplayBytesSent = 0;
        DisplayBytesReceived = 0;
        DisplayDroppedEvents = 0;
        _completedRuntime = TimeSpan.Zero;
        RuntimeText = "00:00:00";
        Snapshot = Array.Empty<NetworkEvent>();
        Summary = CaptureAnalyzer.Summarize(Array.Empty<NetworkEvent>());
        _snapshotDirty = false;
        SnapshotUpdated?.Invoke(this, EventArgs.Empty);
    }

    private void ApplySummaryMetrics(CaptureSummary summary)
    {
        lock (_metricsGate)
        {
            _sessionEvents = summary.EventCount;
            _sessionBytesSent = summary.BytesSent;
            _sessionBytesReceived = summary.BytesReceived;
            _flowSnapshots.Clear();
        }

        DisplayEventCount = summary.EventCount;
        DisplayBytesSent = summary.BytesSent;
        DisplayBytesReceived = summary.BytesReceived;
    }

    private static IEnumerable<DnsObservation> BuildDnsObservations(IEnumerable<NetworkEvent> events) =>
        events
            .SelectMany(networkEvent => networkEvent.DnsNames.Select(name => new DnsObservation(
                networkEvent.TimestampUtc,
                networkEvent.Pid,
                name,
                networkEvent.RemoteIp,
                DnsObservationKind.Response,
                networkEvent.DnsCorrelation == DnsCorrelationState.Cached ? "Cached correlation" : "Best-effort correlation")))
            .DistinctBy(observation => (observation.TimestampUtc, observation.Pid, observation.QueryName, observation.Address))
            .OrderBy(observation => observation.TimestampUtc);

    private static long Delta(long previous, long current)
    {
        var safe = Math.Max(0, current);
        return safe >= previous ? safe - previous : safe;
    }

    private static string FlowKey(NetworkEvent networkEvent) =>
        $"{networkEvent.Pid}|{networkEvent.LocalIp}|{networkEvent.LocalPort}|{networkEvent.RemoteIp}|{networkEvent.RemotePort}|{networkEvent.Protocol}";

    private static string FormatRuntime(TimeSpan runtime) =>
        $"{(int)runtime.TotalHours:00}:{runtime.Minutes:00}:{runtime.Seconds:00}";

    public void Dispose()
    {
        _uiTimer.Stop();
        StopRecording();
        _captureSession.Dispose();
    }

    private readonly record struct FlowSnapshot(long BytesSent, long BytesReceived);
}
