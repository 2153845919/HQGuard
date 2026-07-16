using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HQGuard;

/// <summary>
/// 域名管理 + WFP 拦截器
/// 定时解析域名 → 增量更新 WFP 过滤规则
/// </summary>
class DomainBlocker : IDisposable
{
    public record DomainConfig(string Domain, int[] Ports);

    readonly DomainConfig[] _domains;
    readonly Guid _subLayerKey = Guid.NewGuid();
    readonly CancellationTokenSource _cts = new();
    readonly TimeSpan _resolveInterval = TimeSpan.FromSeconds(1);

    IntPtr _engine = IntPtr.Zero;
    Dictionary<string, HashSet<IPAddress>> _currentIps = new();
    Dictionary<string, Guid> _filterKeys = new(); // "ip:port" → filterKey
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
        _running = true;

        if (!WfpEngine.Available)
        {
            Log("[WFP] 当前环境不支持 Windows Filtering Platform");
            _running = false;
            return;
        }

        // 打开 WFP 引擎
        int ret = WfpEngine.EngineOpen(out _engine);
        if (ret != 0)
        {
            Log($"[WFP] 打开引擎失败 ({ret})，请以管理员身份运行");
            _running = false;
            return;
        }

        // 添加子层
        var sl = new WfpEngine.FWPM_SUBLAYER
        {
            subLayerKey = _subLayerKey,
            weight = 0x100
        };
        ret = WfpEngine.SubLayerAdd(_engine, ref sl);
        if (ret != 0)
        {
            Log($"[WFP] 添加子层失败 ({ret})");
            WfpEngine.EngineClose(_engine);
            _engine = IntPtr.Zero;
            _running = false;
            return;
        }

        Log("[WFP] 引擎就绪");

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
                        AddFilter(ip, port);

                foreach (var ip in removed)
                    foreach (var port in dc.Ports)
                        RemoveFilter(ip, port);

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

    void AddFilter(IPAddress ip, int port)
    {
        var key = $"{ip}:{port}";
        if (_filterKeys.ContainsKey(key)) return;

        var filterGuid = Guid.NewGuid();
        var filter = new WfpEngine.FWPM_FILTER
        {
            filterKey = filterGuid,
            layerKey = WfpEngine.LayerAleAuthConnectV4,
            subLayerKey = _subLayerKey,
            weight = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_EMPTY },
            action = new WfpEngine.FWPM_ACTION { actionType = WfpEngine.FWP_ACTION_BLOCK },
            numFilterConditions = 2
        };

        // Condition 1: remote addr matches
        var bytes = ip.GetAddressBytes();
        uint ipVal = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
        var c1 = new WfpEngine.FWPM_FILTER_CONDITION
        {
            fieldKey = WfpEngine.AleRemoteAddr,
            matchType = WfpEngine.FWP_MATCH_EQUAL,
            conditionValue = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_UINT32, value = ipVal }
        };

        // Condition 2: remote port matches
        var c2 = new WfpEngine.FWPM_FILTER_CONDITION
        {
            fieldKey = WfpEngine.AleRemotePort,
            matchType = WfpEngine.FWP_MATCH_EQUAL,
            conditionValue = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_UINT16, value = (ulong)port }
        };

        // Marshal conditions
        var conds = new[] { c1, c2 };
        int condSize = Marshal.SizeOf<WfpEngine.FWPM_FILTER_CONDITION>();
        IntPtr condPtr = Marshal.AllocHGlobal(condSize * 2);
        long baseAddr = condPtr.ToInt64();
        Marshal.StructureToPtr(c1, new IntPtr(baseAddr), false);
        Marshal.StructureToPtr(c2, new IntPtr(baseAddr + condSize), false);
        filter.filterCondition = condPtr;

        int ret = WfpEngine.FilterAdd(_engine, ref filter);
        Marshal.FreeHGlobal(condPtr);

        if (ret == 0)
        {
            _filterKeys[key] = filterGuid;
            Log($"[拦截] {ip}:{port}");
        }
        else
        {
            Log($"[WFP] 添加拦截失败 {ip}:{port} (err:{ret})");
        }
    }

    void RemoveFilter(IPAddress ip, int port)
    {
        var key = $"{ip}:{port}";
        if (!_filterKeys.TryGetValue(key, out var guid)) return;

        var g = guid;
        WfpEngine.FilterDelete(_engine, ref g);
        _filterKeys.Remove(key);
        Log($"[放行] {ip}:{port} (IP已变更)");
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Stop()
    {
        _running = false;
        _cts.Cancel();

        if (_engine == IntPtr.Zero) return;

        // 清理所有过滤规则
        foreach (var (key, guid) in _filterKeys)
        {
            var g = guid;
            WfpEngine.FilterDelete(_engine, ref g);
        }
        _filterKeys.Clear();

        // 删除子层
        var slk = _subLayerKey;
        WfpEngine.SubLayerDelete(_engine, ref slk);

        // 关闭引擎
        WfpEngine.EngineClose(_engine);
        _engine = IntPtr.Zero;

        Log("[WFP] 已清理所有规则");
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
