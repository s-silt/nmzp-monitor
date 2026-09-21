// NMZP native egress filter — PInvoke and WFP struct layouts.
// Constants and field order copied from Windows SDK 10.0.22621.0 headers.
// Target: x64 only. Layout mismatch refuses apply/cleanup.

using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Nmzp.NativeEgressFilter
{
    internal static class WfpGuids
    {
        // um/fwpmu.h FWPM_LAYER_ALE_AUTH_CONNECT_V4
        // c38d57d1-05a7-4c33-904f-7fbceee60e82
        public static readonly Guid LayerAleAuthConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");

        // um/fwpmu.h FWPM_LAYER_ALE_AUTH_CONNECT_V6
        // 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
        public static readonly Guid LayerAleAuthConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

        // um/fwpmu.h FWPM_CONDITION_ALE_PACKAGE_ID
        // 71bc78fa-f17c-4997-a602-6abb261f351c
        public static readonly Guid CondAlePackageId = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");

        // um/fwpmu.h FWPM_CONDITION_IP_REMOTE_ADDRESS
        // b235ae9a-1d64-49b8-a44c-5ff3d9095045
        public static readonly Guid CondIpRemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

        // um/fwpmu.h FWPM_CONDITION_IP_PROTOCOL
        // 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
        public static readonly Guid CondIpProtocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

        // um/fwpmu.h FWPM_CONDITION_IP_REMOTE_PORT
        // c35a604d-d22b-4e1a-91b4-68f674ee674b
        public static readonly Guid CondIpRemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");

        // um/fwpmu.h FWPM_SUBLAYER_UNIVERSAL (read-only compare; never modified)
        public static readonly Guid SubLayerUniversal = new Guid("eebecc03-ced4-4380-819a-2734397b2b74");

        // um/fwpmu.h FWPM_SUBLAYER_MPSSVC_WF (read-only compare; never modified)
        public static readonly Guid SubLayerMpssvcWf = new Guid("b3cdd441-af90-41ba-a745-7c6008ff2301");

        // NMZP-owned objects. Not Windows built-in.
        public static readonly Guid Provider = new Guid("7d4e1c8a-3f92-4b6e-a15d-9c80e2b47f31");
        public static readonly Guid SubLayer = new Guid("a19b5e70-2c4d-4f81-b6c3-8e5a1d9f7024");
    }

    internal static class WfpConst
    {
        // shared/rpcdce.h
        public const uint RpcCAuthnWinnt = 10;

        // shared/fwptypes.h FWP_DATA_TYPE_
        public const int FwpEmpty = 0;
        public const int FwpUint8 = 1;
        public const int FwpUint16 = 2;
        public const int FwpUint32 = 3;
        public const int FwpUint64 = 4;
        public const int FwpSid = 13;

        // shared/fwptypes.h FWP_MATCH_TYPE_
        public const int FwpMatchEqual = 0;

        // shared/fwptypes.h
        public const uint FwpActionFlagTerminating = 0x00001000;
        public const uint FwpActionBlock = 0x00000001 | FwpActionFlagTerminating;
        public const uint FwpActionPermit = 0x00000002 | FwpActionFlagTerminating;

        // shared/fwpmtypes.h
        public const uint FwpmFilterFlagNone = 0;
        public const uint FwpmFilterFlagPersistent = 0x00000001;
        public const uint FwpmFilterFlagClearActionRight = 0x00000008;
        public const uint FwpmProviderFlagPersistent = 0x00000001;
        public const uint FwpmSubLayerFlagPersistent = 0x00000001;
        public const uint FwpmSessionFlagDynamic = 0x00000001;

        // shared/ws2def.h IPPROTO_TCP
        public const byte IpProtoTcp = 6;

        // 127.0.0.1 as FWP_UINT32 host-order (MSDN: IPv4 in host order)
        public const uint Ipv4LoopbackHostOrder = 0x7F000001;

        public const ushort SubLayerWeight = 0xF000;
        public const byte WeightAllow = 15;
        public const byte WeightBlock = 1;

        // shared/winerror.h
        public const uint FwpENotFound = 0x80320008;
        public const uint FwpEAlreadyExists = 0x80320009;
        public const uint FwpEInUse = 0x8032000A;
        public const uint ErrorSuccess = 0;
        public const uint ErrorAccessDenied = 5;
        public const uint ErrorFileNotFound = 2;
        public const uint ErrorPathNotFound = 3;
        public const uint ErrorInvalidParameter = 87;
        public const uint ErrorNotFound = 1168;

        public const int TokenUser = 1;
        public const int TokenGroups = 2;
        public const int TokenSessionId = 12;
        public const int TokenElevation = 20;
        public const int TokenIsAppContainer = 29;
        public const int TokenAppContainerSid = 31;
        public const int TokenIsLessPrivilegedAppContainer = 46;
        public const int MaxFilterConditions = 8;
        public const int MaxTokenGroups = 128;
        public const int MaxTokenInfoBytes = 65536;
        public const int AclSizeInformation = 2;
        public const byte AccessAllowedAceType = 0;
        public const int JobObjectBasicUIRestrictions = 4;
        public const uint JobUiHandles = 0x00000001;
        public const uint JobUiReadClipboard = 0x00000002;
        public const uint JobUiWriteClipboard = 0x00000004;
        public const uint JobUiDesktop = 0x00000040;
        public const uint JobUiExitWindows = 0x00000080;
        public const uint JobUiRequired = JobUiHandles | JobUiReadClipboard | JobUiWriteClipboard | JobUiDesktop | JobUiExitWindows;
        public const uint TokenQuery = 0x0008;
        public const uint ProcessQueryLimitedInformation = 0x1000;
        public const uint JobObjectQuery = 0x0004;
        public const uint ReadControl = 0x00020000;
        public const int JobObjectBasicAccountingInformation = 1;
        public const int JobObjectBasicProcessIdList = 3;
        public const int JobObjectExtendedLimitInformation = 9;
        public const uint JobObjectLimitBreakawayOk = 0x00000800;
        public const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
        public const uint JobObjectLimitKillOnJobClose = 0x00002000;
        public const int SeKernelObject = 6;
        public const uint ErrorMoreData = 234;

        public const int SddlRevision1 = 1;
        public const int SeFileObject = 1;
        public const uint OwnerSecurityInformation = 0x00000001;
        public const uint DaclSecurityInformation = 0x00000004;
        public const uint ProtectedDaclSecurityInformation = 0x80000000;
        public const uint FileAttributeReparsePoint = 0x00000400;
        public const uint InvalidFileAttributes = 0xFFFFFFFF;
        public const string SidLocalSystem = "S-1-5-18";
        public const string SidAdministrators = "S-1-5-32-544";

        public const int LayoutFilterSize = 200;
        public const int LayoutSessionSize = 72;
        public const int LayoutProviderSize = 64;
        public const int LayoutSubLayerSize = 72;
        public const int LayoutValueSize = 16;
        public const int LayoutConditionSize = 40;
        public const int LayoutActionSize = 20;
        public const int LayoutBlobSize = 16;
        public const int LayoutDisplaySize = 16;
        public const int LayoutSidAttrSize = 16;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FwpByteBlob
    {
        [FieldOffset(0)] public uint size;
        [FieldOffset(8)] public IntPtr data;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FwpDisplayData0
    {
        [FieldOffset(0)] public IntPtr name;
        [FieldOffset(8)] public IntPtr description;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FwpValue0
    {
        [FieldOffset(0)] public int type;
        [FieldOffset(8)] public IntPtr value;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FwpConditionValue0
    {
        [FieldOffset(0)] public int type;
        [FieldOffset(8)] public IntPtr value;
    }

    [StructLayout(LayoutKind.Explicit, Size = 20)]
    internal struct FwpmAction0
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(4)] public Guid filterType;
    }

    [StructLayout(LayoutKind.Explicit, Size = 40)]
    internal struct FwpmFilterCondition0
    {
        [FieldOffset(0)] public Guid fieldKey;
        [FieldOffset(16)] public int matchType;
        [FieldOffset(24)] public FwpConditionValue0 conditionValue;
    }

    [StructLayout(LayoutKind.Explicit, Size = 200)]
    internal struct FwpmFilter0
    {
        [FieldOffset(0)] public Guid filterKey;
        [FieldOffset(16)] public FwpDisplayData0 displayData;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(40)] public IntPtr providerKey;
        [FieldOffset(48)] public FwpByteBlob providerData;
        [FieldOffset(64)] public Guid layerKey;
        [FieldOffset(80)] public Guid subLayerKey;
        [FieldOffset(96)] public FwpValue0 weight;
        [FieldOffset(112)] public uint numFilterConditions;
        [FieldOffset(120)] public IntPtr filterCondition;
        [FieldOffset(128)] public FwpmAction0 action;
        [FieldOffset(152)] public Guid providerContextKey;
        [FieldOffset(168)] public IntPtr reserved;
        [FieldOffset(176)] public ulong filterId;
        [FieldOffset(184)] public FwpValue0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Explicit, Size = 64)]
    internal struct FwpmProvider0
    {
        [FieldOffset(0)] public Guid providerKey;
        [FieldOffset(16)] public FwpDisplayData0 displayData;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(40)] public FwpByteBlob providerData;
        [FieldOffset(56)] public IntPtr serviceName;
    }

    [StructLayout(LayoutKind.Explicit, Size = 72)]
    internal struct FwpmSubLayer0
    {
        [FieldOffset(0)] public Guid subLayerKey;
        [FieldOffset(16)] public FwpDisplayData0 displayData;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(40)] public IntPtr providerKey;
        [FieldOffset(48)] public FwpByteBlob providerData;
        [FieldOffset(64)] public ushort weight;
    }

    [StructLayout(LayoutKind.Explicit, Size = 72)]
    internal struct FwpmSession0
    {
        [FieldOffset(0)] public Guid sessionKey;
        [FieldOffset(16)] public FwpDisplayData0 displayData;
        [FieldOffset(32)] public uint flags;
        [FieldOffset(36)] public uint txnWaitTimeoutInMSec;
        [FieldOffset(40)] public uint processId;
        [FieldOffset(48)] public IntPtr sid;
        [FieldOffset(56)] public IntPtr username;
        [FieldOffset(64)] public int kernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TokenAppContainerInformation
    {
        public IntPtr TokenAppContainer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AclSizeInformation
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicUiRestrictions
    {
        public uint UIRestrictionsClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
        public uint TotalProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicProcessIdList
    {
        public uint NumberOfAssignedProcesses;
        public uint NumberOfProcessIdsInList;
    }

    internal static class Native
    {
        public static int FwpmFilterAddCalls;
        public static int FwpmFilterDeleteCalls;
        public static int FwpmProviderAddCalls;
        public static int FwpmSubLayerAddCalls;
        public static int ExemptionSetCalls;
        public static int ExemptionGetCalls;

        public static void ResetMutationCounters()
        {
            FwpmFilterAddCalls = 0;
            FwpmFilterDeleteCalls = 0;
            FwpmProviderAddCalls = 0;
            FwpmSubLayerAddCalls = 0;
            ExemptionSetCalls = 0;
            ExemptionGetCalls = 0;
        }

        public static int MutationSum()
        {
            return FwpmFilterAddCalls
                + FwpmFilterDeleteCalls
                + FwpmProviderAddCalls
                + FwpmSubLayerAddCalls
                + ExemptionSetCalls;
        }

        [DllImport("fwpuclnt.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint FwpmEngineOpen0(
            string serverName,
            uint authnService,
            IntPtr authIdentity,
            IntPtr session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        static extern uint FwpmProviderAdd0Raw(IntPtr engineHandle, IntPtr provider, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmProviderGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr provider);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        static extern uint FwpmSubLayerAdd0Raw(IntPtr engineHandle, IntPtr subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        static extern uint FwpmFilterAdd0Raw(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        static extern uint FwpmFilterDeleteByKey0Raw(IntPtr engineHandle, ref Guid key);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmFilterGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr filter);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmProviderGetSecurityInfoByKey0(
            IntPtr engineHandle,
            ref Guid key,
            uint securityInfo,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmSubLayerGetSecurityInfoByKey0(
            IntPtr engineHandle,
            ref Guid key,
            uint securityInfo,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        public static extern uint FwpmFilterGetSecurityInfoByKey0(
            IntPtr engineHandle,
            ref Guid key,
            uint securityInfo,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        public static uint FwpmProviderAdd0(IntPtr engineHandle, IntPtr provider, IntPtr sd)
        {
            FwpmProviderAddCalls++;
            return FwpmProviderAdd0Raw(engineHandle, provider, sd);
        }

        public static uint FwpmSubLayerAdd0(IntPtr engineHandle, IntPtr subLayer, IntPtr sd)
        {
            FwpmSubLayerAddCalls++;
            return FwpmSubLayerAdd0Raw(engineHandle, subLayer, sd);
        }

        public static uint FwpmFilterAdd0(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id)
        {
            FwpmFilterAddCalls++;
            return FwpmFilterAdd0Raw(engineHandle, filter, sd, out id);
        }

        public static uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key)
        {
            FwpmFilterDeleteCalls++;
            return FwpmFilterDeleteByKey0Raw(engineHandle, ref key);
        }

        [DllImport("FirewallAPI.dll", ExactSpelling = true)]
        static extern uint NetworkIsolationGetAppContainerConfigRaw(out uint pdwNumPublicAppCs, out IntPtr appContainerSids);

        [DllImport("FirewallAPI.dll", ExactSpelling = true)]
        static extern uint NetworkIsolationSetAppContainerConfigRaw(uint dwNumPublicAppCs, IntPtr appContainerSids);

        public static uint NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr sids)
        {
            ExemptionGetCalls++;
            return NetworkIsolationGetAppContainerConfigRaw(out count, out sids);
        }

        public static uint NetworkIsolationSetAppContainerConfig(uint count, IntPtr sids)
        {
            ExemptionSetCalls++;
            return NetworkIsolationSetAppContainerConfigRaw(count, sids);
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out IntPtr ppsid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

        [DllImport("advapi32.dll")]
        public static extern IntPtr FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll")]
        public static extern bool EqualSid(IntPtr a, IntPtr b);

        [DllImport("advapi32.dll")]
        public static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll")]
        public static extern int GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll")]
        public static extern bool CopySid(int nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            int stringSDRevision,
            out IntPtr securityDescriptor,
            IntPtr securityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            out bool lpbDaclPresent,
            out IntPtr pDacl,
            out bool lpbDaclDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint SetNamedSecurityInfo(
            string pObjectName,
            int objectType,
            uint securityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetAclInformation(IntPtr pacl, IntPtr info, int length, int infoClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetAce(IntPtr pacl, uint dwAceIndex, out IntPtr pAce);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            uint securityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetNamedSecurityInfo(
            string pObjectName,
            int objectType,
            uint securityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetFileAttributes(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateDirectory(string lpPathName, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentProcessId();

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcessHeap();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            int tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool K32EnumProcesses(int[] processIds, int cb, out int cbNeeded);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenJobObject(uint dwDesiredAccess, bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryInformationJobObject(
            IntPtr hJob,
            int jobObjectInformationClass,
            IntPtr lpJobObjectInformation,
            uint cbJobObjectInformationLength,
            IntPtr lpReturnLength);

        public static bool TrySidToString(IntPtr sid, out string text)
        {
            text = null;
            if (sid == IntPtr.Zero)
            {
                return false;
            }
            IntPtr p = IntPtr.Zero;
            try
            {
                if (!ConvertSidToStringSid(sid, out p) || p == IntPtr.Zero)
                {
                    return false;
                }
                text = Marshal.PtrToStringUni(p);
                return !string.IsNullOrEmpty(text);
            }
            finally
            {
                if (p != IntPtr.Zero)
                {
                    LocalFree(p);
                }
            }
        }

        public static bool TryDerivePackageSid(string profileName, out string sidText, out string error)
        {
            sidText = null;
            error = null;
            IntPtr sid = IntPtr.Zero;
            try
            {
                int hr = DeriveAppContainerSidFromAppContainerName(profileName, out sid);
                if (hr != 0 || sid == IntPtr.Zero)
                {
                    error = "derive_sid_failed_hr=0x" + hr.ToString("X8");
                    return false;
                }
                if (!IsValidSid(sid))
                {
                    error = "derived_sid_invalid";
                    return false;
                }
                if (!TrySidToString(sid, out sidText))
                {
                    error = "sid_stringify_failed";
                    return false;
                }
                if (!sidText.StartsWith("S-1-15-2-", StringComparison.Ordinal))
                {
                    error = "derived_sid_not_appcontainer";
                    sidText = null;
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = "derive_sid_exception:" + ex.GetType().Name;
                return false;
            }
            finally
            {
                if (sid != IntPtr.Zero)
                {
                    FreeSid(sid);
                }
            }
        }

        public static bool LayoutOk(out string error)
        {
            error = null;
            if (IntPtr.Size != 8)
            {
                error = "platform_not_x64";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpValue0)) != WfpConst.LayoutValueSize)
            {
                error = "layout_FwpValue0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpConditionValue0)) != WfpConst.LayoutValueSize)
            {
                error = "layout_FwpConditionValue0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpByteBlob)) != WfpConst.LayoutBlobSize)
            {
                error = "layout_FwpByteBlob";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpDisplayData0)) != WfpConst.LayoutDisplaySize)
            {
                error = "layout_FwpDisplayData0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmAction0)) != WfpConst.LayoutActionSize)
            {
                error = "layout_FwpmAction0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmFilterCondition0)) != WfpConst.LayoutConditionSize)
            {
                error = "layout_FwpmFilterCondition0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmFilter0)) != WfpConst.LayoutFilterSize)
            {
                error = "layout_FwpmFilter0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmProvider0)) != WfpConst.LayoutProviderSize)
            {
                error = "layout_FwpmProvider0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmSubLayer0)) != WfpConst.LayoutSubLayerSize)
            {
                error = "layout_FwpmSubLayer0";
                return false;
            }
            if (Marshal.SizeOf(typeof(FwpmSession0)) != WfpConst.LayoutSessionSize)
            {
                error = "layout_FwpmSession0";
                return false;
            }
            if (Marshal.SizeOf(typeof(SidAndAttributes)) != WfpConst.LayoutSidAttrSize)
            {
                error = "layout_SidAndAttributes";
                return false;
            }
            return true;
        }

        public static bool IsElevatedAdmin()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                if (id == null)
                {
                    return false;
                }
                WindowsPrincipal p = new WindowsPrincipal(id);
                return p.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        public static string CurrentUserSid()
        {
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                if (id == null || id.User == null)
                {
                    return null;
                }
                return id.User.Value;
            }
            catch
            {
                return null;
            }
        }

        public static bool OwnerSidTrusted(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return false;
            if (string.Equals(sid, WfpConst.SidLocalSystem, StringComparison.Ordinal)) return true;
            if (string.Equals(sid, WfpConst.SidAdministrators, StringComparison.Ordinal)) return true;
            string me = CurrentUserSid();
            if (!string.IsNullOrEmpty(me) && string.Equals(sid, me, StringComparison.Ordinal)) return true;
            return false;
        }

        public static bool FileAttrsAreReparse(uint attrs)
        {
            if (attrs == WfpConst.InvalidFileAttributes) return false;
            return (attrs & WfpConst.FileAttributeReparsePoint) != 0;
        }
    }
}
