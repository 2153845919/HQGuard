using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HQGuard;

/// <summary>
/// 域名管理 + 防火墙规则管理
/// 定时解析域名 → 增量增删防火墙规则
/// </summary>
class DomainBlocker : IDisposable
{
    public record DomainConfig(string Domain, int[] Ports);

    readonly DomainConfig[] _domains;
    readonly CancellationTokenSource _cts = new();
    readonly TimeSpan _resolveInterval = TimeSpan.FromSeconds(1);

    Dictionary<string, HashSet<IPAddress>> _currentIps = new();
    bool _running;

    public bool Running => _running;

    public event Action<string>? OnLog;

    public DomainBlocker(params DomainConfig[] domains)
    {
        _domains = domains;
    }

    public async Task StartAsync()
    {
        if (_running) return;

        if (!FirewallEngine.Available)
        {
            Log("[防火墙] 不可用，请以管理员身份运行");
            return;
        }

        _running = true;
        Log("[防火墙] 引擎就绪: " + (FirewallEngine.ActiveBackend == FirewallEngine.Backend.Wfp ? "WFP" : "iptables"));

        // 初次解析
        await ResolveAndApply();

        // 定时刷新
        _ = Task.Run(() => RefreshLoop(_cts.Token));
    }

    async Task RefreshLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(_resolveInterval, ct); } catch { break; }
            if (ct.IsCancellationRequested) break;
            await ResolveAndApply();
        }
    }

    async Task ResolveAndApply()
    {
        var newMap = new Dictionary<string, HashSet<IPAddress>>();

        foreach (var dc in _domains)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(dc.Domain);
                var ips = addrs.Where(x => x.AddressFamily == AddressFamily.InterNetwork).ToHashSet();
                newMap[dc.Domain] = ips;

                var oldIps = _currentIps.GetValueOrDefault(dc.Domain, new HashSet<IPAddress>());
                var added = ips.Except(oldIps).ToList();
                var removed = oldIps.Except(ips).ToList();

                foreach (var ip in added)
                    foreach (var port in dc.Ports)
                        FirewallEngine.AddBlock(ip.ToString(), port);

                foreach (var ip in removed)
                    foreach (var port in dc.Ports)
                        FirewallEngine.RemoveBlock(ip.ToString(), port);

                if (added.Count > 0 || removed.Count > 0)
                    Log($"[DNS] {dc.Domain} → {string.Join(", ", ips)} (更新 {added.Count}+ {removed.Count}-)");
            }
            catch (Exception ex)
            {
                Log($"[DNS] 解析失败 {dc.Domain}: {ex.Message}");
            }
        }

        _currentIps = newMap;
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Stop()
    {
        _running = false;
        _cts.Cancel();
        FirewallEngine.RemoveAll();
        Log("[防火墙] 已清理所有规则");
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
