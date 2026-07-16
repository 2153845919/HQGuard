using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HQGuard;

/// <summary>
/// WFP API wrapper — 运行时动态加载 fwpuclnt.dll，兼容 Win10/Win11，
/// 不支持的环境（Wine、旧系统）优雅降级。
/// </summary>
static class WfpEngine
{
    static IntPtr _lib = IntPtr.Zero;
    static bool _init;
    static bool _available;

    // Delegates
    delegate int OpenFn(string? server, uint authn, IntPtr auth, ref FWPM_SESSION s, out IntPtr h);
    delegate int CloseFn(IntPtr h);
    delegate int SubLayerAddFn(IntPtr h, ref FWPM_SUBLAYER sl, IntPtr sd);
    delegate int SubLayerDelFn(IntPtr h, ref Guid key);
    delegate int FilterAddFn(IntPtr h, ref FWPM_FILTER f, IntPtr sd, out ulong id);
    delegate int FilterDelFn(IntPtr h, ref Guid key);

    static OpenFn? _open;
    static CloseFn? _close;
    static SubLayerAddFn? _addSl;
    static SubLayerDelFn? _delSl;
    static FilterAddFn? _addF;
    static FilterDelFn? _delF;

    public static bool Available
    {
        get { EnsureInit(); return _available; }
    }

    static void EnsureInit()
    {
        if (_init) return;
        _init = true;
        try
        {
            if (!NativeLibrary.TryLoad("fwpuclnt.dll", out _lib))
            {
                Debug.WriteLine("[WFP] fwpuclnt.dll not found");
                return;
            }
            _open    = Load<OpenFn>("FwpmEngineOpen");
            _close   = Load<CloseFn>("FwpmEngineClose");
            _addSl   = Load<SubLayerAddFn>("FwpmSubLayerAdd");
            _delSl   = Load<SubLayerDelFn>("FwpmSubLayerDeleteByKey");
            _addF    = Load<FilterAddFn>("FwpmFilterAdd");
            _delF    = Load<FilterDelFn>("FwpmFilterDeleteByKey");
            _available = _open != null;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WFP] Init failed: {ex.Message}");
        }
    }

    static T? Load<T>(string name) where T : class
    {
        if (!NativeLibrary.TryGetExport(_lib, name, out var addr)) return null;
        return Marshal.GetDelegateForFunctionPointer<T>(addr);
    }

    public static int EngineOpen(out IntPtr handle)
    {
        EnsureInit();
        handle = IntPtr.Zero;
        if (_open == null) return -1;
        var s = new FWPM_SESSION { flags = FWPM_SESSION_FLAG_DYNAMIC };
        return _open(null, 0, IntPtr.Zero, ref s, out handle);
    }

    public static int EngineClose(IntPtr h)
    {
        if (_close == null) return -1;
        return _close(h);
    }

    public static int SubLayerAdd(IntPtr engine, ref FWPM_SUBLAYER sl)
    {
        if (_addSl == null) return -1;
        return _addSl(engine, ref sl, IntPtr.Zero);
    }

    public static int SubLayerDelete(IntPtr engine, ref Guid key)
    {
        if (_delSl == null) return -1;
        return _delSl(engine, ref key);
    }

    public static int FilterAdd(IntPtr engine, ref FWPM_FILTER filter)
    {
        if (_addF == null) return 0;
        return _addF(engine, ref filter, IntPtr.Zero, out _);
    }

    public static int FilterDelete(IntPtr engine, ref Guid key)
    {
        if (_delF == null) return 0;
        return _delF(engine, ref key);
    }

    // ── WFP 结构 ──

    const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SESSION
    {
        public uint flags;
        public uint sessionId;
        public int txnId;
        public IntPtr username;
        public IntPtr sid;
        public uint sessionKey0;
        public uint sessionKey1;
        public uint sessionKey2;
        public uint sessionKey3;
        public IntPtr dynamicSessionKey;
        public uint processId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER
    {
        public Guid filterKey;
        public IntPtr displayData;
        public uint flags;
        public IntPtr providerKey;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE weight;
        public int numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION action;
        public IntPtr rawContext;
        public IntPtr providerContextKey;
        public IntPtr reserved;
        public long filterId;
        public IntPtr effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_ACTION
    {
        public uint actionType;
        public IntPtr calloutKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_VALUE
    {
        public uint type;
        public ulong value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER_CONDITION
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_VALUE conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SUBLAYER
    {
        public Guid subLayerKey;
        public IntPtr displayData;
        public uint flags;
        public IntPtr providerKey;
        public ushort weight;
        public ushort reserved;
    }

    // Layer / condition GUIDs
    public static readonly Guid LayerAleAuthConnectV4 = new("5ace2f4f-12e3-44e1-a36e-3e8a789ad4d6");
    public static readonly Guid AleRemotePort = new("618a9b6d-3866-4250-a2ad-7b9955adb65e");
    public static readonly Guid AleRemoteAddr = new("0bb42c1e-6a6c-11d2-97f7-0000f810ab50"); // FWPM_CONDITION_IP_REMOTE_ADDRESS

    public const uint FWP_ACTION_BLOCK = 0x00000002;
    public const uint FWP_EMPTY = 0;
    public const uint FWP_UINT16 = 0x00000002;
    public const uint FWP_UINT32 = 0x00000003;
    public const uint FWP_MATCH_EQUAL = 1;
}
