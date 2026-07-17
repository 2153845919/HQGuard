using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HQGuard;

/// <summary>
/// 多后端拦截引擎 — 自动选择可用方案
/// 优先级: WinDivert > iptables > hosts
/// </summary>
class Blocker : IDisposable
{
    // ── WinDivert ──
    const string DivertDll = "WinDivert64.dll";
    [DllImport(DivertDll, CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr WinDivertOpen(string filter, uint priority, ulong flags);
    [DllImport(DivertDll, CallingConvention = CallingConvention.Cdecl)]
    static extern bool WinDivertClose(IntPtr handle);
    [DllImport(DivertDll, CallingConvention = CallingConvention.Cdecl)]
    static extern bool WinDivertRecv(IntPtr handle, IntPtr pPacket, uint packetLen, ref uint recvLen, ref WinDivertAddress addr);

    struct WinDivertAddress { public long _1; public byte _2,_3; public ushort _4; public uint _5,_6,_7,_8,_9,_10,_11; }

    enum Backend { None, WinDivert, Iptables, Hosts }

    Backend _backend = Backend.None;
    IntPtr _divertHandle = IntPtr.Zero;
    Thread? _divertThread;
    volatile bool _running;
    readonly CancellationTokenSource _cts = new();
    readonly string[] _domains = { "cschannel.anticheatexpert.com", "cschannel2.anticheatexpert.com" };
    readonly int[] _ports = { 80, 443 };
    HashSet<string> _currentIps = new();
    HashSet<string> _hostsEntries = new();

    public bool Available => _backend != Backend.None;
    public event Action<string>? OnLog;

    public Blocker()
    {
        DetectBackend();
    }

    void DetectBackend()
    {
        // 1. WinDivert
        try
        {
            var h = WinDivertOpen("false", 0, 0);
            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                WinDivertClose(h);
                _backend = Backend.WinDivert;
                Log("[引擎] WinDivert");
                return;
            }
        }
        catch { }

        // 2. iptables (Wine/Linux)
        try
        {
            using var p = new Process { StartInfo = new ProcessStartInfo("iptables","--version") { UseShellExecute=false, CreateNoWindow=true } };
            p.Start(); p.WaitForExit(2000);
            if (p.ExitCode == 0)
            {
                _backend = Backend.Iptables;
                Log("[引擎] iptables (Linux)");
                return;
            }
        }
        catch { }

        // 3. hosts 文件
        try
        {
            string hosts = Environment.OSVersion.Platform == PlatformID.Win32NT
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers/etc/hosts")
                : "/etc/hosts";
            if (File.Exists(hosts) && (File.GetAttributes(hosts) & FileAttributes.ReadOnly) != FileAttributes.ReadOnly)
            {
                _backend = Backend.Hosts;
                Log("[引擎] hosts 文件");
                return;
            }
        }
        catch { }

        Log("[引擎] 无可用后端");
    }

    public async Task StartAsync()
    {
        if (_running) return;
        if (_backend == Backend.None) { Log("[错误] 无可用拦截引擎"); return; }

        _running = true;
        await RefreshIps();

        switch (_backend)
        {
            case Backend.WinDivert: StartDivert(); break;
            case Backend.Iptables: ApplyIptables(); break;
            case Backend.Hosts: ApplyHosts(); break;
        }

        _ = Task.Run(() => RefreshLoop(_cts.Token));
    }

    async Task RefreshLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(1000, ct); } catch { break; }
            var oldIps = new HashSet<string>(_currentIps);
            await RefreshIps();
            if (!_currentIps.SetEquals(oldIps))
            {
                Log($"[DNS] IP 变更，更新规则");
                switch (_backend)
                {
                    case Backend.WinDivert: RestartDivert(); break;
                    case Backend.Iptables: ApplyIptables(); break;
                    case Backend.Hosts: ApplyHosts(); break;
                }
            }
        }
    }

    async Task RefreshIps()
    {
        _currentIps.Clear();
        foreach (var domain in _domains)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(domain);
                foreach (var a in addrs)
                    if (a.AddressFamily == AddressFamily.InterNetwork)
                        _currentIps.Add(a.ToString());
                Log($"[DNS] {domain}");
            }
            catch { Log($"[DNS] 解析失败 {domain}"); }
        }
    }

    // ── WinDivert ──
    void StartDivert()
    {
        if (_currentIps.Count == 0) return;
        var parts = new List<string>();
        foreach (var ip in _currentIps)
            foreach (var port in _ports)
                parts.Add($"(outbound and tcp.DstPort=={port} and ip.DstAddr=={ip})");
        var filter = string.Join(" or ", parts);
        _divertHandle = WinDivertOpen(filter, 0, 0);
        if (_divertHandle == IntPtr.Zero || _divertHandle == new IntPtr(-1)) { Log("[WinDivert] 打开过滤器失败"); return; }
        _divertThread = new Thread(() => {
            var buf = Marshal.AllocHGlobal(65535);
            var addr = new WinDivertAddress();
            while (_running) { uint r=0; if(!WinDivertRecv(_divertHandle,buf,65535,ref r,ref addr)) break; }
            Marshal.FreeHGlobal(buf);
        }) { IsBackground = true, Name = "DivertRecv" };
        _divertThread.Start();
        Log($"[WinDivert] 拦截中 ({_currentIps.Count} IPs)");
    }

    void RestartDivert()
    {
        _running = false;
        if (_divertHandle != IntPtr.Zero) { WinDivertClose(_divertHandle); _divertHandle = IntPtr.Zero; }
        _divertThread?.Join(1000);
        _running = true;
        StartDivert();
    }

    // ── iptables ──
    void ApplyIptables()
    {
        // 先清理旧的
        foreach (var ip in _currentIps)
            foreach (var port in _ports)
                RunIptables($"-D OUTPUT -d {ip} -p tcp --dport {port} -j DROP");
        // 添加新的
        foreach (var ip in _currentIps)
            foreach (var port in _ports)
                RunIptables($"-A OUTPUT -d {ip} -p tcp --dport {port} -j DROP");
        Log($"[iptables] 拦截中 ({_currentIps.Count} IPs)");
    }

    void RunIptables(string args)
    {
        try { using var p = new Process { StartInfo = new ProcessStartInfo("iptables", args) { UseShellExecute = false, CreateNoWindow = true } }; p.Start(); p.WaitForExit(2000); }
        catch { }
    }

    // ── hosts ──
    void ApplyHosts()
    {
        string hostsPath = Environment.OSVersion.Platform == PlatformID.Win32NT
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers/etc/hosts")
            : "/etc/hosts";
        try
        {
            var lines = File.ReadAllLines(hostsPath);
            var newLines = new List<string>();
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                bool skip = false;
                foreach (var domain in _domains)
                    if (trimmed.EndsWith(" " + domain) || trimmed.EndsWith("\t" + domain))
                    { skip = true; break; }
                if (!skip) newLines.Add(line);
            }
            foreach (var domain in _domains)
                newLines.Add($"127.0.0.1 {domain}");
            File.WriteAllLines(hostsPath, newLines);
            // 刷新DNS缓存
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                RunIptables(""); // no-op, just for Process
            Log($"[hosts] 已添加 {_domains.Length} 域名 → 127.0.0.1");
        }
        catch (Exception ex) { Log($"[hosts] 写入失败: {ex.Message}"); }
    }

    void CleanupHosts()
    {
        string hostsPath = Environment.OSVersion.Platform == PlatformID.Win32NT
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers/etc/hosts")
            : "/etc/hosts";
        try
        {
            var lines = File.ReadAllLines(hostsPath);
            var newLines = new List<string>();
            foreach (var line in lines)
            {
                bool skip = false;
                foreach (var domain in _domains)
                    if (line.Trim().EndsWith(" " + domain) || line.Trim().EndsWith("\t" + domain))
                    { skip = true; break; }
                if (!skip) newLines.Add(line);
            }
            File.WriteAllLines(hostsPath, newLines);
            Log("[hosts] 已清理");
        }
        catch { }
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Stop()
    {
        _running = false;
        _cts.Cancel();
        if (_backend == Backend.WinDivert && _divertHandle != IntPtr.Zero)
        { WinDivertClose(_divertHandle); _divertHandle = IntPtr.Zero; _divertThread?.Join(1000); }
        if (_backend == Backend.Iptables)
            foreach (var ip in _currentIps)
                foreach (var port in _ports)
                    RunIptables($"-D OUTPUT -d {ip} -p tcp --dport {port} -j DROP");
        if (_backend == Backend.Hosts) CleanupHosts();
        Log("[引擎] 已停止");
    }

    public void Dispose() { Stop(); _cts.Dispose(); }
}
