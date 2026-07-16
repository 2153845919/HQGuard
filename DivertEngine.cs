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
/// WinDivert 引擎 — 内核级网络包拦截
/// 需同目录下有 WinDivert64.dll 和 WinDivert64.sys（已签名）
/// </summary>
class DivertEngine : IDisposable
{
    const string Dll = "WinDivert64.dll";

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr WinDivertOpen(string filter, uint priority, ulong flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    static extern bool WinDivertRecv(IntPtr handle, IntPtr pPacket, uint packetLen, ref uint recvLen, ref WinDivertAddress addr);

    [StructLayout(LayoutKind.Sequential)]
    struct WinDivertAddress
    {
        public long Timestamp;
        public byte Layer;
        public byte Event;
        public ushort Sniffed;
        public uint Outbound;
        public uint Loopback;
        public uint Impostor;
        public uint PseudoChecksum;
        public uint PseudoIPChecksum;
        public uint Reserved;
    }

    IntPtr _handle = IntPtr.Zero;
    Thread? _recvThread;
    volatile bool _running;
    CancellationTokenSource _cts = new();

    public bool Available { get; private set; }
    public event Action<string>? OnLog;

    public DivertEngine()
    {
        Available = CheckAvailable();
    }

    static bool CheckAvailable()
    {
        try
        {
            var h = WinDivertOpen("false", 0, 0);
            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                WinDivertClose(h);
                return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// 启动拦截 — 过滤出站 TCP 到指定 IP:端口
    /// 匹配的包直接丢弃（不 re-inject）
    /// </summary>
    public bool Start(string[] ips, int[] ports)
    {
        if (!Available)
        {
            Log("[WinDivert] 驱动不可用");
            return false;
        }

        // 构建过滤器
        var parts = new List<string>();
        foreach (var ip in ips)
            foreach (var port in ports)
                parts.Add($"(outbound and tcp.DstPort=={port} and ip.DstAddr=={ip})");
        var filter = string.Join(" or ", parts);

        if (string.IsNullOrEmpty(filter))
        {
            Log("[WinDivert] 过滤器为空");
            return false;
        }

        _handle = WinDivertOpen(filter, 0, 0);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            Log("[WinDivert] 打开过滤器失败");
            return false;
        }

        _running = true;
        _recvThread = new Thread(RecvLoop) { IsBackground = true, Name = "WinDivertRecv" };
        _recvThread.Start();

        Log($"[WinDivert] 拦截已启动 ({filter})");
        return true;
    }

    void RecvLoop()
    {
        const uint bufSize = 65535;
        IntPtr buf = Marshal.AllocHGlobal((int)bufSize);
        var addr = new WinDivertAddress();

        while (_running)
        {
            uint recvLen = 0;
            // 阻塞等待匹配的包，收到后不 re-inject → 包被丢弃
            bool ok = WinDivertRecv(_handle, buf, bufSize, ref recvLen, ref addr);
            if (!ok)
            {
                // handle 被关闭，退出循环
                break;
            }
            // 不调用 WinDivertSend → 包被静默丢弃
        }

        Marshal.FreeHGlobal(buf);
    }

    public void Stop()
    {
        _running = false;
        _cts.Cancel();

        if (_handle != IntPtr.Zero)
        {
            WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }

        _recvThread?.Join(2000);
        Log("[WinDivert] 已停止");
    }

    void Log(string msg) => OnLog?.Invoke(msg);

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
