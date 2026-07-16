using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace HQGuard;

public partial class MainWindow : Window
{
    readonly DomainBlocker _blocker;
    readonly HeartbeatMonitor _monitor;
    bool _isRunning;

    public MainWindow()
    {
        InitializeComponent();
        Log("程序已启动");

        FirewallEngine.LogCallback = msg => Log(msg);

        _blocker = new DomainBlocker(
            new DomainBlocker.DomainConfig("cschannel.anticheatexpert.com", new[] { 80, 443 }),
            new DomainBlocker.DomainConfig("cschannel2.anticheatexpert.com", new[] { 80, 443 })
        );
        _blocker.OnLog += msg => Log(msg);

        _monitor = new HeartbeatMonitor();
        _monitor.OnLog += msg => Log(msg);
        _monitor.OnHeartbeatLost += OnHeartbeatLost;

        // 检测防火墙状态
        _ = CheckFirewall();
    }

    async System.Threading.Tasks.Task CheckFirewall()
    {
        if (FirewallEngine.Init())
        {
            WfpStatus.Text = FirewallEngine.ActiveBackend == FirewallEngine.Backend.Wfp
                ? "WFP ✓" : "iptables ✓";
            WfpStatus.Foreground = new SolidColorBrush(Colors.Green);
        }
        else
        {
            WfpStatus.Text = "不可用";
            WfpStatus.Foreground = new SolidColorBrush(Colors.Red);
        }
    }

    async void ToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning)
            await StopAsync();
        else
            await StartAsync();
    }

    async System.Threading.Tasks.Task StartAsync()
    {
        ToggleBtn.IsEnabled = false;
        ToggleBtn.Content = "启动中...";

        try
        {
            await _blocker.StartAsync();
            if (!_blocker.Running)
            {
                ToggleBtn.Content = "开启过检测";
                ToggleBtn.IsEnabled = true;
                return;
            }

            _monitor.Start();

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

        _monitor.Stop();
        _blocker.Stop();
        _isRunning = false;

        StatusDot.Fill = new SolidColorBrush(Colors.Gray);
        BlockStatus.Text = "已停止";
        BlockStatus.Foreground = new SolidColorBrush(Colors.Gray);
        ToggleBtn.Content = "开启过检测";
        ToggleBtn.IsEnabled = true;
        Log("[系统] 过检测已关闭");
    }

    void OnHeartbeatLost()
    {
        Dispatcher.Invoke(() =>
        {
            var result = MessageBox.Show(
                "服务器维护中\n请及时查看更新信息，避免拉闸",
                "提示",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.OK)
            {
                _ = StopAsync();
            }
        });
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
