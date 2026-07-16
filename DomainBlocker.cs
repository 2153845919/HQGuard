using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HQGuard;

/// <summary>
/// 域名管理 + 拦截控制
/// 定时解析域名 → 更新 WinDivert 拦截规则
/// </summary>
class DomainBlocker : IDisposable
{
    public record DomainConfig(string Domain, int[] Ports);

    readonly DomainConfig[] _domains;
    readonly DivertEngine _divert;
    readonly CancellationTokenSource _cts = new();
    readonly TimeSpan _resolveInterval = TimeSpan.FromSeconds(1);

    Dictionary<string, HashSet<IPAddress>> _currentIps = new();
    bool _running;

    public bool Running => _running;
    public bool EngineOk => _divert.Available;

    public event Action<string>? OnLog;

    public DomainBlocker(DivertEngine divert, params DomainConfig[] domains)
    {
        _divert = divert;
        _domains = domains;
        _divert.OnLog += msg => Log(msg);
    }

    public async Task StartAsync()
    {
        if (_running) return;
        if (!_divert.Available)
        {
            Log("[WinDivert] 驱动不可用，请确认 WinDivert64.sys 和 WinDivert64.dll 是否存在");
            return;
        }

        _running = true;

        // 首次解析并启动拦截
        var allIps = await ResolveAll();
        if (allIps.Count > 0)
        {
            var ports = _domains.SelectMany(d => d.Ports).Distinct().ToArray();
            var ipStrs = allIps.Select(ip => ip.ToString()).ToArray();
            _divert.Start(ipStrs, ports);
        }

        // 定时刷新
        _ = Task.Run(() => RefreshLoop(_cts.Token));
    }

    async Task RefreshLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(_resolveInterval, ct); } catch { break; }
            if (ct.IsCancellationRequested) break;

            var newIps = await ResolveAll();
            var oldIps = _currentIps.Values.SelectMany(s => s).ToHashSet();
            var added = newIps.Except(oldIps).ToList();
            var removed = oldIps.Except(newIps).ToList();

            if (added.Count > 0 || removed.Count > 0)
            {
                // IP 有变化 → 重启拦截器
                _divert.Stop();
                var allIps = newIps.ToList();
                if (allIps.Count > 0)
                {
                    var ports = _domains.SelectMany(d => d.Ports).Distinct().ToArray();
                    _divert.Start(allIps.Select(ip => ip.ToString()).ToArray(), ports);
                }
            }
        }
    }

    async Task<HashSet<IPAddress>> ResolveAll()
    {
        var allIps = new HashSet<IPAddress>();
        foreach (var dc in _domains)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(dc.Domain);
                var ips = addrs.Where(x => x.AddressFamily == AddressFamily.InterNetwork).ToHashSet();
                allIps.UnionWith(ips);
                Log($"[DNS] {dc.Domain} → {string.Join(", ", ips)}");
            }
            catch (Exception ex)
            {
                Log($"[DNS] 解析失败 {dc.Domain}: {ex.Message}");
            }
        }
        _currentIps = new Dictionary<string, HashSet<IPAddress>>();
        foreach (var dc in _domains)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(dc.Domain);
                _currentIps[dc.Domain] = addrs.Where(x => x.AddressFamily == AddressFamily.InterNetwork).ToHashSet();
            }
            catch { }
        }
        return allIps;
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Stop()
    {
        _running = false;
        _cts.Cancel();
        _divert.Stop();
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
        _divert.Dispose();
    }
}
