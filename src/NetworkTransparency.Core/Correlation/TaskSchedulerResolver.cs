using System.Runtime.InteropServices;
using NetworkTransparency.Core.Models;

namespace NetworkTransparency.Core.Correlation;

internal sealed class TaskSchedulerResolver
{
    private readonly object _gate = new();
    private DateTime _lastRefreshUtc = DateTime.MinValue;
    private IReadOnlyList<ScheduledTaskSnapshot> _cached = Array.Empty<ScheduledTaskSnapshot>();

    public IReadOnlyList<TaskCorrelation> GetTasksNear(DateTime timestampUtc)
    {
        EnsureCache();
        var window = TimeSpan.FromMinutes(5);

        return _cached
            .Where(task => Math.Abs((task.LastRunUtc - timestampUtc).TotalMinutes) <= window.TotalMinutes)
            .Select(task => new TaskCorrelation(
                task.Name,
                task.Path,
                task.LastRunUtc,
                (task.LastRunUtc - timestampUtc).Duration(),
                task.State))
            .OrderBy(task => task.Distance)
            .Take(12)
            .ToArray();
    }

    private void EnsureCache()
    {
        if (DateTime.UtcNow - _lastRefreshUtc <= TimeSpan.FromMinutes(2))
        {
            return;
        }

        lock (_gate)
        {
            if (DateTime.UtcNow - _lastRefreshUtc <= TimeSpan.FromMinutes(2))
            {
                return;
            }

            _cached = LoadTasks();
            _lastRefreshUtc = DateTime.UtcNow;
        }
    }

    private static IReadOnlyList<ScheduledTaskSnapshot> LoadTasks()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<ScheduledTaskSnapshot>();
        }

        dynamic? service = null;
        dynamic? root = null;
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType is null)
            {
                return Array.Empty<ScheduledTaskSnapshot>();
            }

            service = Activator.CreateInstance(schedulerType);
            service!.Connect();
            root = service.GetFolder("\\");
            var tasks = new List<ScheduledTaskSnapshot>();
            ReadFolder(root, tasks);
            return tasks;
        }
        catch
        {
            return Array.Empty<ScheduledTaskSnapshot>();
        }
        finally
        {
            ReleaseCom(root);
            ReleaseCom(service);
        }
    }

    private static void ReadFolder(dynamic folder, List<ScheduledTaskSnapshot> output)
    {
        if (output.Count >= 5000)
        {
            return;
        }

        dynamic? tasks = null;
        try
        {
            tasks = folder.GetTasks(0);
            foreach (dynamic task in tasks)
            {
                try
                {
                    var lastRun = (DateTime)task.LastRunTime;
                    if (lastRun.Year > 1900)
                    {
                        output.Add(new ScheduledTaskSnapshot(
                            (string)task.Name,
                            (string)task.Path,
                            DateTime.SpecifyKind(lastRun, DateTimeKind.Local).ToUniversalTime(),
                            StateName((int)task.State)));
                    }
                }
                catch
                {
                }
                finally
                {
                    ReleaseCom(task);
                }
            }
        }
        catch
        {
        }
        finally
        {
            ReleaseCom(tasks);
        }

        dynamic? folders = null;
        try
        {
            folders = folder.GetFolders(0);
            foreach (dynamic child in folders)
            {
                try
                {
                    ReadFolder(child, output);
                }
                finally
                {
                    ReleaseCom(child);
                }
            }
        }
        catch
        {
        }
        finally
        {
            ReleaseCom(folders);
        }
    }

    private static string StateName(int state) => state switch
    {
        1 => "Disabled",
        2 => "Queued",
        3 => "Ready",
        4 => "Running",
        _ => "Unknown"
    };

    private static void ReleaseCom(object? value)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            if (value is not null && Marshal.IsComObject(value))
            {
                Marshal.FinalReleaseComObject(value);
            }
        }
        catch
        {
        }
    }

    private sealed record ScheduledTaskSnapshot(
        string Name,
        string Path,
        DateTime LastRunUtc,
        string State);
}
