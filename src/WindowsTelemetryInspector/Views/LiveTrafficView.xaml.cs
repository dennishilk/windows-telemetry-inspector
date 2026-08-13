using System.Windows.Controls;
using System.Windows.Input;
using NetworkTransparency.Core.Models;
using WindowsTelemetryInspector.ViewModels;

namespace WindowsTelemetryInspector.Views;

public partial class LiveTrafficView : UserControl
{
    private LiveTrafficViewModel? _viewModel;

    public LiveTrafficView()
    {
        InitializeComponent();
    }

    private void OnLoaded(object sender, System.Windows.RoutedEventArgs e)
    {
        _viewModel = DataContext as LiveTrafficViewModel;
        if (_viewModel is not null)
        {
            _viewModel.Workspace.EventsAppended += OnEventsAppended;
        }
    }

    private void OnUnloaded(object sender, System.Windows.RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.Workspace.EventsAppended -= OnEventsAppended;
            _viewModel = null;
        }
    }

    private void OnEventsAppended(object? sender, NetworkEvent networkEvent)
    {
        if (_viewModel?.Workspace.Settings.AutoScroll != true || !_viewModel.EventsView.Contains(networkEvent))
        {
            return;
        }

        EventGrid.ScrollIntoView(networkEvent);
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.K && Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
        }
    }
}
