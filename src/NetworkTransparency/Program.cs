using System.Text.Json;
using NetworkTransparency.Core.Analysis;
using NetworkTransparency.Core.Capture;
using NetworkTransparency.Core.Models;
using NetworkTransparency.Core.Persistence;

namespace NetworkTransparency;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintHelp();
            return 0;
        }

        var parseResult = CliOptions.Parse(args.Skip(1).ToArray());
        if (!parseResult.IsValid)
        {
            Console.Error.WriteLine(parseResult.Error);
            Console.Error.WriteLine();
            PrintHelp();
            return 2;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "live" => await RunLiveAsync(parseResult.Options!),
                "record" => await RunRecordAsync(parseResult.Options!),
                "summary" => RunSummary(parseResult.Options!),
                _ => UnknownCommand(args[0])
            };
        }
        catch (CapturePermissionException error)
        {
            Console.Error.WriteLine(error.Message);
            Console.Error.WriteLine("Open an elevated terminal and try again.");
            return 3;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"Fatal error: {error.Message}");
            return 1;
        }
    }

    private static async Task<int> RunLiveAsync(CliOptions options)
    {
        using var sink = new TextWriterEventSink(Console.Out);
        await RunCaptureAsync(options, sink);
        return 0;
    }

    private static async Task<int> RunRecordAsync(CliOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.OutputPath))
        {
            Console.Error.WriteLine("record requires --output <path>.");
            return 2;
        }

        using var sink = new JsonlEventSink(options.OutputPath);
        Console.WriteLine($"Recording JSONL to {sink.Path}");
        await RunCaptureAsync(options, sink);
        return 0;
    }

    private static async Task RunCaptureAsync(CliOptions options, IEventSink sink)
    {
        using var session = new EtwCaptureSession();
        using var cancellation = new CancellationTokenSource();
        var captureFault = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        Console.CancelKeyPress += cancelHandler;
        if (options.DurationSeconds.HasValue)
        {
            cancellation.CancelAfter(TimeSpan.FromSeconds(options.DurationSeconds.Value));
        }

        session.StatusChanged += (_, status) =>
        {
            Console.Error.WriteLine(status.Message);
            if (status.State == CaptureState.Faulted)
            {
                captureFault.TrySetResult(status.Error ?? new InvalidOperationException(status.Message));
                cancellation.Cancel();
            }
        };

        try
        {
            await session.StartAsync(new CaptureOptions(options.IncludeDns), sink, cancellation.Token);
            Console.Error.WriteLine("Passive capture started. Press Ctrl+C to stop.");
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellation.Token);
            }
            catch (OperationCanceledException)
            {
            }
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            await session.StopAsync();
        }

        if (captureFault.Task.IsCompletedSuccessfully)
        {
            throw new InvalidOperationException(
                $"The capture stopped unexpectedly: {captureFault.Task.Result.Message}",
                captureFault.Task.Result);
        }
    }

    private static int RunSummary(CliOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.InputPath))
        {
            Console.Error.WriteLine("summary requires --input <path>.");
            return 2;
        }

        var loaded = JsonlCaptureStore.Read(options.InputPath);
        var summary = CaptureAnalyzer.Summarize(loaded.Events);

        Console.WriteLine("Windows Telemetry Inspector capture summary");
        Console.WriteLine($"Events:   {summary.EventCount:N0}");
        Console.WriteLine($"Duration: {FormatDuration(summary.Duration)}");
        Console.WriteLine($"Sent:     {FormatBytes(summary.BytesSent)}");
        Console.WriteLine($"Received: {FormatBytes(summary.BytesReceived)}");
        if (loaded.MalformedLineCount > 0)
        {
            Console.WriteLine($"Warning: skipped {loaded.MalformedLineCount:N0} malformed JSONL line(s).");
        }

        PrintAggregates("Top processes", summary.TopProcesses);
        PrintAggregates("Top remote hosts", summary.TopRemoteHosts);
        PrintAggregates("Top categories", summary.TopCategories);
        PrintAggregates("Top services", summary.TopServices);
        return 0;
    }

    private static void PrintAggregates(string title, IEnumerable<TrafficAggregate> aggregates)
    {
        Console.WriteLine();
        Console.WriteLine($"{title}:");
        foreach (var aggregate in aggregates)
        {
            Console.WriteLine(
                $"  {aggregate.Key} — {aggregate.Events:N0} events, " +
                $"sent {FormatBytes(aggregate.BytesSent)}, received {FormatBytes(aggregate.BytesReceived)}");
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = Math.Max(0, bytes);
        var unit = 0;
        var display = (double)value;
        while (display >= 1024 && unit < units.Length - 1)
        {
            display /= 1024;
            unit++;
        }

        return unit == 0 ? $"{value:N0} {units[unit]}" : $"{display:N1} {units[unit]}";
    }

    private static string FormatDuration(TimeSpan duration) =>
        duration.TotalHours >= 1
            ? $"{(int)duration.TotalHours:00}:{duration.Minutes:00}:{duration.Seconds:00}"
            : $"{duration.Minutes:00}:{duration.Seconds:00}";

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Console.Error.WriteLine();
        PrintHelp();
        return 2;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Windows Telemetry Inspector CLI (.NET 8 / Windows 11)\n");
        Console.WriteLine("Passive observation only — no blocking, no MITM, no kernel driver.\n");
        Console.WriteLine("Usage:");
        Console.WriteLine("  WindowsTelemetryInspector.Cli.exe live [--duration <seconds>] [--include-dns]");
        Console.WriteLine("  WindowsTelemetryInspector.Cli.exe record --output <path> [--duration <seconds>] [--include-dns]");
        Console.WriteLine("  WindowsTelemetryInspector.Cli.exe summary --input <path>");
    }
}

internal sealed record CliOptions(
    string? OutputPath,
    string? InputPath,
    int? DurationSeconds,
    bool IncludeDns)
{
    public static CliParseResult Parse(string[] args)
    {
        string? output = null;
        string? input = null;
        int? duration = null;
        var includeDns = false;

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--output":
                    if (!TryReadValue(args, ref index, out output))
                    {
                        return CliParseResult.Invalid("--output requires a path.");
                    }

                    break;
                case "--input":
                    if (!TryReadValue(args, ref index, out input))
                    {
                        return CliParseResult.Invalid("--input requires a path.");
                    }

                    break;
                case "--duration":
                    if (!TryReadValue(args, ref index, out var durationValue) ||
                        !int.TryParse(durationValue, out var parsedDuration) || parsedDuration <= 0)
                    {
                        return CliParseResult.Invalid("--duration requires a positive whole number of seconds.");
                    }

                    duration = parsedDuration;
                    break;
                case "--include-dns":
                    includeDns = true;
                    break;
                default:
                    return CliParseResult.Invalid($"Unknown option: {args[index]}");
            }
        }

        return CliParseResult.Valid(new CliOptions(output, input, duration, includeDns));
    }

    private static bool TryReadValue(string[] args, ref int index, out string? value)
    {
        value = args.ElementAtOrDefault(index + 1);
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith("--", StringComparison.Ordinal))
        {
            value = null;
            return false;
        }

        index++;
        return true;
    }
}

internal sealed record CliParseResult(CliOptions? Options, string? Error)
{
    public bool IsValid => Options is not null;

    public static CliParseResult Valid(CliOptions options) => new(options, null);
    public static CliParseResult Invalid(string error) => new(null, error);
}

internal sealed class TextWriterEventSink : IEventSink
{
    private readonly TextWriter _writer;

    public TextWriterEventSink(TextWriter writer)
    {
        _writer = writer;
    }

    public void Write(NetworkEvent networkEvent) =>
        _writer.WriteLine(JsonSerializer.Serialize(networkEvent, CaptureJson.Options));

    public void Dispose()
    {
    }
}
