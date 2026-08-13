# Windows verification

Use this checklist on Windows 11 x64 before publishing a release. Automated builds validate compilation, tests, publish output, and a basic process-start smoke test; ETW and visual behavior still require a real interactive Windows session.

## Automated baseline

```powershell
dotnet restore .\NetworkTransparency.sln
dotnet build .\NetworkTransparency.sln -c Release --no-restore
dotnet run --project .\src\NetworkTransparency.Tests\NetworkTransparency.Tests.csproj -c Release --no-build -- -nocolor
dotnet publish .\src\WindowsTelemetryInspector\WindowsTelemetryInspector.csproj -c Release -p:PublishProfile=win-x64 --no-restore
```

Confirm the publish folder contains `WindowsTelemetryInspector.exe` and no separately installed runtime is required.

## Interactive capture checks

1. Start the application as a standard user.
2. Confirm elevation is visibly reported as **No**.
3. Start capture. If the kernel provider is denied, confirm the app remains open, explains the limitation, and offers explicit restart elevation.
4. Restart elevated and confirm the state changes through **STARTING**, **CAPTURE ACTIVE**, **STOPPING**, and **CAPTURE IDLE**.
5. Generate HTTPS and DNS traffic. Confirm TCP/UDP events populate Live Traffic and runtime/event/byte counters change.
6. Stop and restart capture. Confirm no stale ETW session error occurs.
7. Select an event. Confirm event fields, process metadata, services, DNS state, and correlated-task language render without claiming causality.
8. Search by process and host, then filter by PID, protocol, category, service, and DNS. Clear the filters and confirm the original rows return.
9. Record a capture, stop it, and confirm the JSONL file grows and appears under Captures.
10. Reopen that capture and a CLI capture. Confirm summary totals and details load.
11. Open a file containing a malformed line. Confirm valid events load and the skipped-line warning is visible.
12. Make the capture folder unwritable and attempt recording/export. Confirm a useful error is shown and the app does not crash.
13. Terminate a short-lived process before selecting its event. Confirm unavailable metadata is labeled **Unknown**, **Not available**, or **Not resolved**.

## CLI compatibility checks

In an elevated PowerShell terminal:

```powershell
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -c Release -- live --include-dns --duration 15
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -c Release -- record --include-dns --duration 15 --output .\captures\smoke.jsonl
dotnet run --project .\src\NetworkTransparency\NetworkTransparency.csproj -c Release -- summary --input .\captures\smoke.jsonl
```

Confirm live output is structured JSON, recording produces non-empty JSONL after traffic is generated, and summary succeeds.

## Layout and accessibility checks

At 100% and 150% display scaling, inspect both 1366×768 and 1920×1080:

- Resize to the documented minimum and maximize/restore.
- Confirm navigation, capture controls, counters, table headers, detail tabs, dialogs, and bottom status remain readable.
- Confirm dense rows are not clipped and horizontal/vertical scrolling is available where necessary.
- Navigate controls and data grids with the keyboard; verify focus indicators.
- Confirm capture, provider, DNS, and error states are communicated in text as well as color.
- Verify high-volume capture does not freeze selection, filtering, scrolling, or window resizing.

## Public-release boundary

Before a public download is announced:

- Run every interactive check on a clean Windows 11 x64 machine.
- Inspect the executable with Windows Defender and a second reputable scanner.
- Add Authenticode signing and document publisher identity.
- Decide whether to publish symbols and checksums.
- Review capture-file privacy language and dependency licenses.
- Do not create a tag or release until the version and signing decision are approved.
