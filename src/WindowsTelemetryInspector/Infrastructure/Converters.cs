using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace WindowsTelemetryInspector.Infrastructure;

public sealed class BooleanToVisibilityConverter : IValueConverter
{
    public bool Inverse { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var visible = value is true;
        if (Inverse)
        {
            visible = !visible;
        }

        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Visibility visibility && (visibility == Visibility.Visible) != Inverse;
}

public sealed class BytesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not long bytes)
        {
            return "0 B";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var display = (double)Math.Max(0, bytes);
        var unit = 0;
        while (display >= 1024 && unit < units.Length - 1)
        {
            display /= 1024;
            unit++;
        }

        return unit == 0 ? $"{display:N0} {units[unit]}" : $"{display:N1} {units[unit]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class CategoryBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value?.ToString() ?? string.Empty;
        return key switch
        {
            "Windows Update" => Brush("#2578BD"),
            "Microsoft Defender" => Brush("#228755"),
            "Microsoft Store" => Brush("#158B9B"),
            "Telemetry" => Brush("#9A6A25"),
            "Time Sync" => Brush("#7351B7"),
            _ => Brush("#465362")
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;

    private static SolidColorBrush Brush(string value) =>
        new((Color)ColorConverter.ConvertFromString(value));
}

public sealed class ConfidenceBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var confidence = value is double number ? number : 0;
        var color = confidence >= 0.8 ? "#45D47C" : confidence >= 0.55 ? "#E5AD45" : "#9AA7B5";
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class CollectionToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is IEnumerable<string> items)
        {
            var materialized = items.Where(item => !string.IsNullOrWhiteSpace(item)).ToArray();
            return materialized.Length == 0 ? "Not available" : string.Join(", ", materialized);
        }

        return "Not available";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class DateTimeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is DateTime timestamp
            ? timestamp.ToLocalTime().ToString(parameter?.ToString() ?? "HH:mm:ss.fff", culture)
            : "Not available";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}
