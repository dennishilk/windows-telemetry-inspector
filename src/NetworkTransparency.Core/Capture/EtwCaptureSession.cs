using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Capture;

public sealed class EtwCaptureSession : IDisposable
{
    private readonly object _gate = new();
    private TraceEventSession? _session;
    private EventAggregator? _aggregator;
    private Task? _processingTask;
    private TaskCompletionSource? _stopCompletion;
    private IEventSink? _sink;
    private CaptureState _state = CaptureState.Idle;
    private long _lastDroppedEventCount;

    public CaptureState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public long DroppedEventCount
    {
        get
        {
            lock (_gate)
            {
                return _aggregator?.DroppedEventCount ?? _lastDroppedEventCount;
            }
        }
    }

    public event EventHandler<NetworkEvent>? EventReceived;
    public event EventHandler<DnsObservation>? DnsObserved;
    public event EventHandler<CaptureStatus>? StatusChanged;

    public Task StartAsync(CaptureOptions options, IEventSink? additionalSink = null, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("ETW capture is available only on Windows.");
        }

        lock (_gate)
        {
            if (_state is CaptureState.Starting or CaptureState.Active or CaptureState.Stopping)
            {
                throw new InvalidOperationException("A capture session is already active.");
            }

            _state = CaptureState.Starting;
            _stopCompletion = null;
            _lastDroppedEventCount = 0;
        }

        PublishStatus("Starting ETW capture…", false, false);

        var liveSink = new DelegateEventSink(networkEvent => EventReceived?.Invoke(this, networkEvent));
        _sink = additionalSink is null ? liveSink : new CompositeEventSink(liveSink, additionalSink);
        var aggregator = new EventAggregator(_sink);
        aggregator.DnsObserved += (_, observation) => DnsObserved?.Invoke(this, observation);
        aggregator.PipelineFaulted += error =>
        {
            if (State == CaptureState.Active)
            {
                SetFaulted(error, $"Capture output stopped unexpectedly: {error.Message}");
                _ = Task.Run(StopAsync);
            }
        };

        TraceEventSession? session = null;
        var kernelActive = false;
        var dnsActive = false;

        try
        {
            session = new TraceEventSession($"WindowsTelemetryInspector-{Guid.NewGuid():N}")
            {
                StopOnDispose = true
            };

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            kernelActive = true;
            if (options.IncludeDns)
            {
                try
                {
                    session.EnableProvider("Microsoft-Windows-DNS-Client");
                    dnsActive = true;
                }
                catch (Exception error)
                {
                    PublishStatus($"Network capture active; DNS provider unavailable: {error.Message}", kernelActive, false);
                }
            }

            var kernelParser = new KernelTraceEventParser(session.Source);
            kernelParser.TcpIpConnect += aggregator.OnTcpConnect;
            kernelParser.TcpIpRecv += aggregator.OnTcpRecv;
            kernelParser.TcpIpSend += aggregator.OnTcpSend;
            kernelParser.UdpIpSend += aggregator.OnUdpSend;
            kernelParser.UdpIpRecv += aggregator.OnUdpRecv;
            kernelParser.TcpIpConnectIPV6 += aggregator.OnTcpConnectV6;
            kernelParser.TcpIpSendIPV6 += aggregator.OnTcpSendV6;
            kernelParser.TcpIpRecvIPV6 += aggregator.OnTcpRecvV6;
            kernelParser.UdpIpSendIPV6 += aggregator.OnUdpSendV6;
            kernelParser.UdpIpRecvIPV6 += aggregator.OnUdpRecvV6;

            if (dnsActive)
            {
                var dnsParser = new DynamicTraceEventParser(session.Source);
                dnsParser.AddCallbackForProviderEvent("Microsoft-Windows-DNS-Client", "DnsQuery", aggregator.OnDnsQuery);
                dnsParser.AddCallbackForProviderEvent("Microsoft-Windows-DNS-Client", "DnsResponse", aggregator.OnDnsResponse);
            }
        }
        catch (UnauthorizedAccessException error)
        {
            DisposeFailedStart(session, aggregator);
            SetFaulted(error, "Administrator privileges are required to enable the kernel network provider.");
            throw new CapturePermissionException(
                "Administrator privileges are required for full ETW network capture.", error);
        }
        catch (Exception error)
        {
            DisposeFailedStart(session, aggregator);
            SetFaulted(error, $"ETW capture could not start: {error.Message}");
            throw;
        }

        lock (_gate)
        {
            _session = session;
            _aggregator = aggregator;
            _state = CaptureState.Active;
        }

        PublishStatus(
            dnsActive ? "Capture active" : "Capture active; DNS correlation unavailable",
            kernelActive,
            dnsActive);

        var registration = cancellationToken.Register(() => _ = StopAsync());
        _processingTask = Task.Run(() =>
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception error) when (State == CaptureState.Stopping)
            {
                _ = error;
            }
            catch (Exception error)
            {
                SetFaulted(error, $"Capture stopped unexpectedly: {error.Message}");
                _ = Task.Run(StopAsync);
            }
            finally
            {
                registration.Dispose();
            }
        });

        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        TraceEventSession? session;
        Task? processingTask;
        EventAggregator? aggregator;
        IEventSink? sink;
        Task? pendingStop;
        TaskCompletionSource? stopCompletion;
        lock (_gate)
        {
            if (_state == CaptureState.Idle)
            {
                return;
            }

            if (_state == CaptureState.Stopping)
            {
                pendingStop = _stopCompletion?.Task;
                session = null;
                processingTask = null;
                aggregator = null;
                sink = null;
                stopCompletion = null;
            }
            else
            {
                _state = CaptureState.Stopping;
                _stopCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                stopCompletion = _stopCompletion;
                pendingStop = null;
                session = _session;
                processingTask = _processingTask;
                aggregator = _aggregator;
                sink = _sink;
            }
        }

        if (pendingStop is not null)
        {
            await pendingStop.ConfigureAwait(false);
            return;
        }

        PublishStatus("Stopping capture…", session is not null, false);

        try
        {
            session?.Stop();
            if (processingTask is not null)
            {
                await Task.WhenAny(processingTask, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
            }
        }
        finally
        {
            try
            {
                lock (_gate)
                {
                    _lastDroppedEventCount = aggregator?.DroppedEventCount ?? 0;
                    _session = null;
                    _processingTask = null;
                    _aggregator = null;
                    _sink = null;
                    _state = CaptureState.Idle;
                }

                session?.Dispose();
                aggregator?.Dispose();
                sink?.Dispose();
                PublishStatus("Capture stopped", false, false);
            }
            finally
            {
                stopCompletion?.TrySetResult();
            }
        }
    }

    private void SetFaulted(Exception error, string message)
    {
        lock (_gate)
        {
            _state = CaptureState.Faulted;
        }

        StatusChanged?.Invoke(this, new CaptureStatus(CaptureState.Faulted, message, false, false, error));
    }

    private void PublishStatus(string message, bool kernelProviderActive, bool dnsProviderActive) =>
        StatusChanged?.Invoke(this, new CaptureStatus(State, message, kernelProviderActive, dnsProviderActive));

    private void DisposeFailedStart(TraceEventSession? session, EventAggregator aggregator)
    {
        session?.Dispose();
        aggregator.Dispose();
        _sink?.Dispose();
        _sink = null;
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }
}

public sealed class CapturePermissionException : InvalidOperationException
{
    public CapturePermissionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
