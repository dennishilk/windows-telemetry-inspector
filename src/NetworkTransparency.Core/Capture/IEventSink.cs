using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Capture;

public interface IEventSink : IDisposable
{
    void Write(NetworkEvent networkEvent);
}

public sealed class DelegateEventSink : IEventSink
{
    private readonly Action<NetworkEvent> _writer;

    public DelegateEventSink(Action<NetworkEvent> writer)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    }

    public void Write(NetworkEvent networkEvent) => _writer(networkEvent);

    public void Dispose()
    {
    }
}

public sealed class CompositeEventSink : IEventSink
{
    private readonly IReadOnlyList<IEventSink> _sinks;

    public CompositeEventSink(params IEventSink[] sinks)
    {
        _sinks = sinks;
    }

    public void Write(NetworkEvent networkEvent)
    {
        foreach (var sink in _sinks)
        {
            sink.Write(networkEvent);
        }
    }

    public void Dispose()
    {
        foreach (var sink in _sinks.Reverse())
        {
            sink.Dispose();
        }
    }
}
