using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace HQGuard;

/// <summary>
/// 心跳监控 — 每15秒探测 125.64.3.49:1235
/// 连续失败 → taskkill SKJH.exe + 弹窗
/// </summary>
class HeartbeatMonitor : IDisposable
{
    readonly string _host = "125.64.3.49";
    readonly int _port = 1235;
    readonly TimeSpan _interval = TimeSpan.FromSeconds(15);
    readonly int _maxRetries = 3;
    readonly CancellationTokenSource _cts = new();
    bool _running;

    public event Action<string>? OnLog;
    public event Action? OnHeartbeatLost;

    public bool Running => _running;

    public void Start()
    {
        if (_running) return;
        _running = true;
        _ = RunLoop(_cts.Token);
    }

    async Task RunLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(_interval, ct); } catch { break; }
            if (ct.IsCancellationRequested) break;

            bool ok = false;
            for (int i = 0; i < _maxRetries; i++)
            {
                if (TryPing())
                {
                    ok = true;
                    break;
                }
                await Task.Delay(1000, CancellationToken.None);
            }

            if (!ok)
            {
                Log("[心跳] 服务器不通！执行保护措施");
                KillSkjh();
                OnHeartbeatLost?.Invoke();
            }
            else
            {
                Log("[心跳] 正常");
            }
        }
    }

    bool TryPing()
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(_host, _port);
            return task.Wait(TimeSpan.FromSeconds(5)) && client.Connected;
        }
        catch { return false; }
    }

    void KillSkjh()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("SKJH"))
            {
                p.Kill();
                p.WaitForExit(3000);
                Log($"[守护] 已终止 SKJH.exe (PID:{p.Id})");
            }
        }
        catch (Exception ex)
        {
            Log($"[守护] 终止SKJH失败: {ex.Message}");
        }
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Stop()
    {
        _running = false;
        _cts.Cancel();
        Log("[心跳] 已停止");
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
