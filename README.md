# Windows 11 Network Transparency

A Windows 11 **Network Transparency** tool that passively observes which components talk to the network, when they do it, where they connect, and how much data is exchanged — **without blocking traffic, MITM, or kernel drivers**.

## What it does
- **ETW-based passive capture** of TCP/UDP events (connect/send/recv) and DNS client events (DNS name correlation currently uses responses).
- Correlates **PID → process name → service names** (when hosted in `svchost` or service-hosted processes).
- Best-effort **"why" correlation** by checking scheduled tasks that ran near the network burst.
- Classifies activity into likely categories such as **Windows Update**, **Defender**, **Telemetry**, **Store**, **Time Sync**, or **Other** with a confidence score.
- Outputs JSONL events for live streaming or recording, and provides a summary report.

## What “why” means here
This tool does **best-effort correlation**, not perfect causality. It looks for scheduled tasks that ran within a small time window around a network event and reports them as *related tasks*. That correlation can be useful for investigation, but it does **not** prove the task directly caused the traffic.

## Privacy & Ethics
- Local observation only; no data is exfiltrated.
- No traffic blocking or modification.
- No TLS interception (no MITM).

## Requirements
- Windows 11 x64
- .NET 8 SDK
- Administrator privileges recommended for full ETW capture

## Build
```powershell
dotnet build .\src\NetworkTransparency\NetworkTransparency.csproj
```

## Run
### Live mode (structured event stream)
```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- live --include-dns
```

### Record mode (JSONL)
```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- record --include-dns --output .\captures\network.jsonl
```

### Summary report
```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -- summary --input .\captures\network.jsonl
```

## JSONL Event Schema
Each line contains a single event with these fields:
- `timestampUtc`
- `pid`
- `processName`
- `user`
- `serviceNames`
- `localIp`
- `localPort`
- `remoteIp`
- `remotePort`
- `protocol`
- `bytesSent`
- `bytesRecv`
- `dnsNames`
- `sniHost` (best-effort, currently null)
- `classification`
- `confidence`
- `relatedTasks`
- `notes`

## Limitations
- Kernel provider requires **Administrator** privileges; without it, you may see partial or no data.
- DNS correlation is best-effort and may miss cached or encrypted DNS.
- SNI correlation is not currently implemented (no TLS interception is performed).
- Scheduled task correlation is a heuristic and may include unrelated tasks.

## Smoke test
A lightweight PowerShell script generates traffic and demonstrates capture.
```powershell
.\scripts\smoke-test.ps1
```

## Repository layout
```
src/NetworkTransparency   # CLI app
scripts/                  # smoke test script
```
