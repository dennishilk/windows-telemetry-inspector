# Windows Telemetry Inspector

Windows Telemetry Inspector is a passive Windows 11 network diagnostics tool. It uses Event Tracing for Windows (ETW) to show which processes and services communicate over the network, when traffic occurs, where it goes, and how much data moves.

It is an inspector, not a blocker: it does not modify traffic, install a driver, disable telemetry, or intercept TLS.

## Principles

- Passive observation only; no firewall or packet changes.
- No man-in-the-middle proxy and no TLS decryption.
- No kernel driver installation.
- No endpoint enrichment requests are sent to third parties.
- DNS and scheduled-task relationships are clearly presented as best-effort correlation, never proven causality.

## Desktop application

The native WPF application follows a restrained Windows diagnostics design and includes:

- Live, virtualized traffic table with search and process, PID, protocol, category, host/IP, service, and DNS filters.
- Selected-event details plus process metadata, associated services, DNS state, and nearby scheduled tasks.
- Process and service traffic aggregates.
- Searchable DNS observations and an adaptive traffic timeline.
- Capture recording, reopening, and JSONL export.
- Summary views for top processes, remote hosts, categories, and services.
- Visible elevation, ETW, DNS-correlation, recording, runtime, event-count, and byte-count states.
- Bounded in-memory retention and batched UI updates for sustained capture rates.

The application remains usable without elevation, but Windows may refuse the kernel ETW provider. The UI explains that state and offers an explicit **Restart elevated** action; it never elevates silently.

## Requirements

- Windows 11 x64
- Administrator privileges for full kernel network capture
- .NET 8 SDK only when building from source

The self-contained release executable does not require the .NET SDK or a separately installed .NET runtime.

## Build from source

From a PowerShell prompt in the repository root:

```powershell
dotnet restore .\NetworkTransparency.sln
dotnet build .\NetworkTransparency.sln -c Release --no-restore
dotnet run --project .\src\NetworkTransparency.Tests\NetworkTransparency.Tests.csproj -c Release --no-build -- -nocolor
```

Run the desktop application:

```powershell
dotnet run --project .\src\WindowsTelemetryInspector\WindowsTelemetryInspector.csproj -c Release
```

## Standalone Windows x64 executable

Build the self-contained, single-file release with:

```powershell
dotnet publish .\src\WindowsTelemetryInspector\WindowsTelemetryInspector.csproj -c Release -p:PublishProfile=win-x64
```

The executable is written to:

```text
src\WindowsTelemetryInspector\bin\Release\net8.0-windows\win-x64\publish\WindowsTelemetryInspector.exe
```

The current build is unsigned. Windows SmartScreen may therefore show a warning until release artifacts are code-signed.

## GUI workflow

1. Start the application. The title/status area shows whether it is elevated.
2. Select **Start Capture**. If Windows denies the ETW provider, use **Restart elevated** after reviewing the prompt.
3. Generate normal network traffic and inspect events in **Live Traffic**.
4. Select a row for locally observed endpoints and best-effort process, service, DNS, and task context.
5. Use **Record Capture** to write while capturing, or **Export JSONL** to save the retained workspace.
6. Use **Captures** or **Open Capture** to reopen existing GUI- or CLI-generated JSONL files.

By default, captures are stored in:

```text
%LOCALAPPDATA%\WindowsTelemetryInspector\Captures
```

The location and in-memory event limit can be changed in **Settings**.

## Command-line compatibility

The existing command-line workflows remain available through a shared core engine.

Live structured output:

```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- live --include-dns
```

Record JSONL (Ctrl+C stops an indefinite capture):

```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- record --include-dns --output .\captures\network.jsonl
```

Record for a fixed duration:

```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- record --duration 60 --output .\captures\network.jsonl
```

Summarize a GUI- or CLI-generated capture:

```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- summary --input .\captures\network.jsonl
```

Run `--help` for all options. ETW capture commands require Windows; `summary` is platform-independent.

## JSONL compatibility

Each line is one JSON event. The original fields are preserved:

- `timestampUtc`, `pid`, `processName`, `user`, `serviceNames`
- `localIp`, `localPort`, `remoteIp`, `remotePort`, `protocol`
- `bytesSent`, `bytesRecv`, `dnsNames`, `sniHost`
- `classification`, `confidence`, `relatedTasks`, `notes`

New optional fields add process, service, direction, ETW-provider, DNS-state, and structured task-correlation metadata. Readers tolerate their absence, so existing CLI captures can still be reopened. Malformed and empty lines are skipped and reported in the GUI instead of terminating the application.

Capture files can contain host names, IP addresses, process paths, command lines, Windows user names, and service/task names. Treat them as diagnostic data and review them before sharing.

## Architecture

| Project | Responsibility |
| --- | --- |
| `NetworkTransparency.Core` | ETW capture, bounded aggregation, process/service/DNS/task correlation, classification, JSONL, filtering, and summaries |
| `WindowsTelemetryInspector` | Native WPF application, application state, batching, virtualization, views, settings, and dialogs |
| `NetworkTransparency` | Backward-compatible `live`, `record`, and `summary` CLI |
| `NetworkTransparency.Tests` | Classification, filtering, aggregation, parsing, and serialization tests |

See [Architecture](docs/ARCHITECTURE.md) and [Windows verification](docs/WINDOWS_VERIFICATION.md) for implementation and release-check details.

## Current limitations

- The kernel network provider normally requires administrator privileges. Without sufficient rights, capture may be partial or unavailable; existing captures remain usable.
- DNS correlation is best effort. Cached results, encrypted DNS, provider availability, PID reuse, and timing can prevent or weaken correlation.
- Nearby scheduled-task execution is a heuristic. A listed task is a possible relationship, not proof that it caused traffic.
- SNI is not collected because the application does not intercept TLS.
- Process, service, signer, and task metadata can be unavailable when a process exits, access is denied, or Windows does not expose it.
- Byte totals are reconstructed from ETW events and should be treated as diagnostic estimates rather than billing-grade counters.
- IPv4 and IPv6 TCP/UDP ETW events are supported, but provider behavior can vary by Windows build.

## Privacy and security

All correlation and capture-file processing is local. The application does not phone home, upload captures, or perform external ASN/geolocation lookups. It does not claim to identify malicious software or provide a privacy score.

## License

[MIT](LICENSE)
