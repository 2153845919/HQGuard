using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace HQGuard;

public partial class MainWindow : Window
{
    readonly Blocker _blocker;
    bool _isRunning;

    public MainWindow()
    {
        InitializeComponent();
        Log("程序已启动");

        _blocker = new Blocker();
        _blocker.OnLog += msg => Log(msg);

        // 显示引擎状态
        if (_blocker.Available)
        {
            EngineStatus.Text = "就绪 ✓";
            EngineStatus.Foreground = new SolidColorBrush(Colors.Green);
        }
        else
        {
            EngineStatus.Text = "不可用";
            EngineStatus.Foreground = new SolidColorBrush(Colors.Red);
        }
    }

    async void ToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning) await StopAsync();
        else await StartAsync();
    }

    async System.Threading.Tasks.Task StartAsync()
    {
        ToggleBtn.IsEnabled = false;
        ToggleBtn.Content = "启动中...";

        try
        {
            await _blocker.StartAsync();
            if (!_blocker.Available)
            {
                Log("[错误] 无法启动，无可用拦截引擎");
                ToggleBtn.Content = "开启过检测";
                ToggleBtn.IsEnabled = true;
                return;
            }

            _isRunning = true;
            StatusDot.Fill = new SolidColorBrush(Colors.Lime);
            BlockStatus.Text = "运行中";
            BlockStatus.Foreground = new SolidColorBrush(Colors.Green);
            ToggleBtn.Content = "关闭过检测";
            ToggleBtn.IsEnabled = true;
            Log("[系统] 过检测已开启");
        }
        catch (Exception ex)
        {
            Log($"[错误] {ex.Message}");
            ToggleBtn.Content = "开启过检测";
            ToggleBtn.IsEnabled = true;
        }
    }

    async System.Threading.Tasks.Task StopAsync()
    {
        ToggleBtn.IsEnabled = false;
        ToggleBtn.Content = "关闭中...";
        Log("正在关闭...");

        _blocker.Stop();
        _isRunning = false;

        StatusDot.Fill = new SolidColorBrush(Colors.Gray);
        BlockStatus.Text = "已停止";
        BlockStatus.Foreground = new SolidColorBrush(Colors.Gray);
        ToggleBtn.Content = "开启过检测";
        ToggleBtn.IsEnabled = true;
        Log("[系统] 过检测已关闭");
    }

    void Log(string msg)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
            LogBox.ScrollToEnd();
        });
    }

    void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Clear();

    async void Window_Closing(object sender, CancelEventArgs e)
    {
        if (_isRunning)
        {
            e.Cancel = true;
            await StopAsync();
            Dispatcher.Invoke(() => Application.Current.Shutdown());
        }
    }
}
