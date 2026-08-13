using Microsoft.Win32;
using System.Windows;

namespace WindowsTelemetryInspector.Services;

public interface IDialogService
{
    string? ChooseOpenCapture();
    string? ChooseSaveCapture(string suggestedName, string initialDirectory);
    bool Confirm(string title, string message);
    void ShowError(string title, string message);
    void ShowInformation(string title, string message);
}

public sealed class DialogService : IDialogService
{
    public string? ChooseOpenCapture()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a Windows Telemetry Inspector capture",
            Filter = "JSONL capture (*.jsonl)|*.jsonl|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public string? ChooseSaveCapture(string suggestedName, string initialDirectory)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save Windows Telemetry Inspector capture",
            Filter = "JSONL capture (*.jsonl)|*.jsonl|All files (*.*)|*.*",
            FileName = suggestedName,
            InitialDirectory = Directory.Exists(initialDirectory) ? initialDirectory : null,
            AddExtension = true,
            DefaultExt = ".jsonl",
            OverwritePrompt = true
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public bool Confirm(string title, string message) =>
        MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

    public void ShowError(string title, string message) =>
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);

    public void ShowInformation(string title, string message) =>
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
}
