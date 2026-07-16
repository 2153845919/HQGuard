using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace HQGuard;

/// <summary>
/// 防火墙引擎 — 多后端自动选择
/// 1. WFP (Windows) — 优先，动态加载 fwpuclnt.dll
/// 2. Linux iptables (Wine) — WFP 不可用时回退
/// </summary>
static class FirewallEngine
{
    public enum Backend { None, Wfp, Iptables }
    public static Backend ActiveBackend { get; private set; } = Backend.None;
    public static bool Available => ActiveBackend != Backend.None;

    // WFP 引擎句柄
    static IntPtr _engine = IntPtr.Zero;
    static Guid? _subLayerKey;
    static readonly Dictionary<string, Guid> _filterKeys = new();

    // iptables 规则跟踪
    static readonly HashSet<string> _iptablesRules = new();

    public static Action<string>? LogCallback { get; set; }

    public static bool Init()
    {
        // 尝试 WFP
        if (WfpEngine.Available)
        {
            int ret = WfpEngine.EngineOpen(out _engine);
            if (ret == 0)
            {
                var slk = Guid.NewGuid();
                var sl = new WfpEngine.FWPM_SUBLAYER { subLayerKey = slk, weight = 0x100 };
                if (WfpEngine.SubLayerAdd(_engine, ref sl) == 0)
                {
                    _subLayerKey = slk;
                    ActiveBackend = Backend.Wfp;
                    Log("[防火墙] 使用 WFP 引擎");
                    return true;
                }
                WfpEngine.EngineClose(_engine);
                _engine = IntPtr.Zero;
            }
        }

        // 回退: Linux iptables (Wine 环境)
        if (TryIptables())
        {
            ActiveBackend = Backend.Iptables;
            Log("[防火墙] 使用 iptables 引擎 (Wine/Linux 回退)");
            return true;
        }

        Log("[防火墙] 无可用防火墙后端");
        return false;
    }

    static bool TryIptables()
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "iptables",
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            p.Start();
            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    public static bool AddBlock(string ip, int port)
    {
        var key = $"{ip}:{port}";
        if (ActiveBackend == Backend.Wfp && _filterKeys.ContainsKey(key)) return true;
        if (ActiveBackend == Backend.Iptables && _iptablesRules.Contains(key)) return true;

        switch (ActiveBackend)
        {
            case Backend.Wfp:
                return AddWfpBlock(ip, port, key);
            case Backend.Iptables:
                return AddIptablesBlock(ip, port, key);
            default:
                return false;
        }
    }

    public static bool RemoveBlock(string ip, int port)
    {
        var key = $"{ip}:{port}";
        switch (ActiveBackend)
        {
            case Backend.Wfp:
                return RemoveWfpBlock(key);
            case Backend.Iptables:
                return RemoveIptablesBlock(key);
            default:
                return false;
        }
    }

    public static void RemoveAll()
    {
        switch (ActiveBackend)
        {
            case Backend.Wfp:
                RemoveAllWfp();
                break;
            case Backend.Iptables:
                RemoveAllIptables();
                break;
        }
        ActiveBackend = Backend.None;
    }

    // ── WFP ──

    static bool AddWfpBlock(string ip, int port, string key)
    {
        var filterGuid = Guid.NewGuid();
        var bytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
        uint ipVal = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);

        var filter = new WfpEngine.FWPM_FILTER
        {
            filterKey = filterGuid,
            layerKey = WfpEngine.LayerAleAuthConnectV4,
            subLayerKey = _subLayerKey!.Value,
            weight = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_EMPTY },
            action = new WfpEngine.FWPM_ACTION { actionType = WfpEngine.FWP_ACTION_BLOCK },
            numFilterConditions = 2
        };

        var c1 = new WfpEngine.FWPM_FILTER_CONDITION
        {
            fieldKey = WfpEngine.AleRemoteAddr,
            matchType = WfpEngine.FWP_MATCH_EQUAL,
            conditionValue = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_UINT32, value = ipVal }
        };
        var c2 = new WfpEngine.FWPM_FILTER_CONDITION
        {
            fieldKey = WfpEngine.AleRemotePort,
            matchType = WfpEngine.FWP_MATCH_EQUAL,
            conditionValue = new WfpEngine.FWP_VALUE { type = WfpEngine.FWP_UINT16, value = (ulong)port }
        };

        int cs = Marshal.SizeOf<WfpEngine.FWPM_FILTER_CONDITION>();
        IntPtr ptr = Marshal.AllocHGlobal(cs * 2);
        long baseAddr = ptr.ToInt64();
        Marshal.StructureToPtr(c1, new IntPtr(baseAddr), false);
        Marshal.StructureToPtr(c2, new IntPtr(baseAddr + cs), false);
        filter.filterCondition = ptr;

        int ret = WfpEngine.FilterAdd(_engine, ref filter);
        Marshal.FreeHGlobal(ptr);

        if (ret == 0)
        {
            _filterKeys[key] = filterGuid;
            Log($"[拦截] {ip}:{port}");
            return true;
        }
        return false;
    }

    static bool RemoveWfpBlock(string key)
    {
        if (!_filterKeys.TryGetValue(key, out var guid)) return false;
        var g = guid;
        WfpEngine.FilterDelete(_engine, ref g);
        _filterKeys.Remove(key);
        return true;
    }

    static void RemoveAllWfp()
    {
        foreach (var (_, guid) in _filterKeys)
        {
            var g = guid;
            WfpEngine.FilterDelete(_engine, ref g);
        }
        _filterKeys.Clear();
        if (_subLayerKey.HasValue)
        {
            var slk = _subLayerKey.Value;
            WfpEngine.SubLayerDelete(_engine, ref slk);
        }
        WfpEngine.EngineClose(_engine);
        _engine = IntPtr.Zero;
    }

    // ── iptables ──

    static bool AddIptablesBlock(string ip, int port, string key)
    {
        var rule = $"-A OUTPUT -d {ip} -p tcp --dport {port} -j DROP";
        if (RunIptables(rule))
        {
            _iptablesRules.Add(key);
            Log($"[拦截] {ip}:{port} (iptables)");
            return true;
        }
        return false;
    }

    static bool RemoveIptablesBlock(string key)
    {
        if (!_iptablesRules.Contains(key)) return false;
        var parts = key.Split(':');
        var rule = $"-D OUTPUT -d {parts[0]} -p tcp --dport {parts[1]} -j DROP";
        RunIptables(rule);
        _iptablesRules.Remove(key);
        return true;
    }

    static void RemoveAllIptables()
    {
        foreach (var key in _iptablesRules)
        {
            var parts = key.Split(':');
            var rule = $"-D OUTPUT -d {parts[0]} -p tcp --dport {parts[1]} -j DROP";
            RunIptables(rule);
        }
        _iptablesRules.Clear();
    }

    static bool RunIptables(string args)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "iptables",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true
                }
            };
            p.Start();
            p.WaitForExit(5000);
            if (p.ExitCode != 0)
            {
                var err = p.StandardError.ReadToEnd();
                Debug.WriteLine($"[iptables] fail: {err.Trim()}");
            }
            return p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[iptables] error: {ex.Message}");
            return false;
        }
    }

    static void Log(string msg) => LogCallback?.Invoke(msg);
}
