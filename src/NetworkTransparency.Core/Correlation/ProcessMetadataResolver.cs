using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Correlation;

internal sealed class ProcessMetadataResolver
{
    public ProcessMetadata Resolve(int pid)
    {
        if (pid <= 0)
        {
            return ProcessMetadata.Unknown(pid);
        }

        if (!OperatingSystem.IsWindows())
        {
            return ProcessMetadata.Unknown(pid);
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var processName = ValueOrUnknown(process.ProcessName);
            var startTimeUtc = TryGet(() => process.StartTime.ToUniversalTime());
            var executablePath = "Not available";
            var commandLine = "Not available";
            var user = "Unknown";
            int? parentPid = null;

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId={pid}");
                using var results = searcher.Get();
                foreach (ManagementObject item in results)
                {
                    executablePath = ValueOrUnavailable(item["ExecutablePath"]?.ToString());
                    commandLine = ValueOrUnavailable(item["CommandLine"]?.ToString());
                    parentPid = TryConvertInt(item["ParentProcessId"]);
                    user = ResolveOwner(item);
                    break;
                }
            }
            catch
            {
                executablePath = TryGet(() => process.MainModule?.FileName) ?? "Not available";
            }

            var description = "Not available";
            var company = "Not available";
            if (!IsUnavailable(executablePath) && File.Exists(executablePath))
            {
                try
                {
                    var version = FileVersionInfo.GetVersionInfo(executablePath);
                    description = ValueOrUnavailable(version.FileDescription);
                    company = ValueOrUnavailable(version.CompanyName);
                }
                catch
                {
                }
            }

            var parentName = ResolveParentName(parentPid);
            var integrity = IntegrityLevelResolver.Resolve(process);
            var signer = ResolveSigner(executablePath);

            return new ProcessMetadata(
                pid,
                processName,
                user,
                description,
                company,
                executablePath,
                commandLine,
                parentPid,
                parentName,
                startTimeUtc,
                integrity,
                signer);
        }
        catch
        {
            return ProcessMetadata.Unknown(pid);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ResolveOwner(ManagementObject item)
    {
        try
        {
            var owner = new string[2];
            var result = Convert.ToInt32(item.InvokeMethod("GetOwner", owner));
            if (result == 0 && !string.IsNullOrWhiteSpace(owner[0]))
            {
                return string.IsNullOrWhiteSpace(owner[1]) ? owner[0] : $"{owner[1]}\\{owner[0]}";
            }
        }
        catch
        {
        }

        return "Unknown";
    }

    private static string ResolveParentName(int? parentPid)
    {
        if (!parentPid.HasValue || parentPid.Value <= 0)
        {
            return "Not resolved";
        }

        try
        {
            using var parent = Process.GetProcessById(parentPid.Value);
            return $"{parent.ProcessName} ({parentPid.Value})";
        }
        catch
        {
            return $"Exited process ({parentPid.Value})";
        }
    }

    private static string ResolveSigner(string executablePath)
    {
        if (IsUnavailable(executablePath) || !File.Exists(executablePath))
        {
            return "Not resolved";
        }

        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(executablePath));
#pragma warning restore SYSLIB0057
            return ValueOrUnavailable(certificate.GetNameInfo(X509NameType.SimpleName, false));
        }
        catch (CryptographicException)
        {
            return "Unsigned or signature unavailable";
        }
        catch
        {
            return "Not resolved";
        }
    }

    private static int? TryConvertInt(object? value)
    {
        try
        {
            return value is null ? null : Convert.ToInt32(value);
        }
        catch
        {
            return null;
        }
    }

    private static T? TryGet<T>(Func<T> getter)
    {
        try
        {
            return getter();
        }
        catch
        {
            return default;
        }
    }

    private static string ValueOrUnknown(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "Unknown" : value;

    private static string ValueOrUnavailable(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "Not available" : value;

    private static bool IsUnavailable(string value) =>
        value.Equals("Not available", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("Unknown", StringComparison.OrdinalIgnoreCase);
}

internal static class IntegrityLevelResolver
{
    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;

    public static string Resolve(Process process)
    {
        if (!OperatingSystem.IsWindows())
        {
            return "Not available";
        }

        try
        {
            if (!OpenProcessToken(process.Handle, TokenQuery, out var token))
            {
                return "Not resolved";
            }

            using (token)
            {
                _ = GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out var length);
                if (length <= 0)
                {
                    return "Not resolved";
                }

                var buffer = Marshal.AllocHGlobal(length);
                try
                {
                    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, length, out _))
                    {
                        return "Not resolved";
                    }

                    var sid = Marshal.ReadIntPtr(buffer);
                    var countPointer = GetSidSubAuthorityCount(sid);
                    var count = Marshal.ReadByte(countPointer);
                    if (count == 0)
                    {
                        return "Not resolved";
                    }

                    var ridPointer = GetSidSubAuthority(sid, (uint)(count - 1));
                    var rid = Marshal.ReadInt32(ridPointer);
                    return rid switch
                    {
                        < 0x1000 => "Untrusted",
                        < 0x2000 => "Low",
                        < 0x3000 => "Medium",
                        < 0x4000 => "High",
                        < 0x5000 => "System",
                        _ => "Protected"
                    };
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        catch
        {
            return "Not resolved";
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);
}
