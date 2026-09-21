// P/Invoke for the native supervisor. C# 5 / .NET Framework 4.x. No third-party deps.
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeAgentSandbox
{
    internal static class Native
    {
        public const int ERROR_ALREADY_EXISTS = 183;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_ACCESS_DENIED = 5;
        public const int ERROR_BROKEN_PIPE = 109;
        public const int ERROR_NO_DATA = 232;
        public const int ERROR_PIPE_NOT_CONNECTED = 233;
        public const int ERROR_INVALID_HANDLE = 6;
        public const int TokenUser = 1;
        public const int TokenSessionId = 12;
        public const int TokenElevationType = 18;
        public const int TokenLinkedToken = 19;
        public const int TokenElevation = 20;
        public const int TokenIsAppContainer = 29;
        public const int TokenAppContainerSid = 31;
        public const int TokenElevationTypeDefault = 1;
        public const int TokenElevationTypeFull = 2;
        public const int TokenElevationTypeLimited = 3;
        public const int ERROR_PRIVILEGE_NOT_HELD = 1314;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_QUERY = 0x0008;
        public const int SecurityImpersonation = 2;
        public const int TokenPrimary = 1;
        public const int TokenImpersonation = 2;
        public const int WinBuiltinAdministratorsSid = 26;
        public const uint LABEL_SECURITY_INFORMATION = 0x00000010;
        public const uint WAIT_OBJECT_0 = 0;
        public const uint WAIT_TIMEOUT = 258;
        public const uint WAIT_FAILED = 0xFFFFFFFF;
        public const uint STILL_ACTIVE = 259;
        public const uint CREATE_SUSPENDED = 0x00000004;
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const short SW_HIDE = 0;
        public const short SW_SHOW = 5;

        public const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
        public const int PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009;
        public const int PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY = 0x0002000F;
        public const uint PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT = 1;

        public const int JobObjectBasicAccountingInformation = 1;
        public const int JobObjectBasicUIRestrictions = 4;
        public const int JobObjectExtendedLimitInformation = 9;
        public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        public const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
        public const uint JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
        public const uint JOB_OBJECT_UILIMIT_HANDLES = 0x00000001;
        public const uint JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002;
        public const uint JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004;
        public const uint JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008;
        public const uint JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010;
        public const uint JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020;
        public const uint JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040;
        public const uint JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080;

        public const uint HANDLE_FLAG_INHERIT = 0x00000001;
        public const uint SE_GROUP_ENABLED = 0x00000004;
        public const uint INFINITE = 0xFFFFFFFF;
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint GENERIC_EXECUTE = 0x20000000;
        public const uint GENERIC_ALL = 0x10000000;
        public const uint READ_CONTROL = 0x00020000;
        public const uint WRITE_DAC = 0x00040000;
        public const uint WRITE_OWNER = 0x00080000;
        public const uint DELETE_RIGHT = 0x00010000;
        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        public const uint WINSTA_ENUMDESKTOPS = 0x0001;
        public const uint WINSTA_READATTRIBUTES = 0x0002;
        public const uint WINSTA_ACCESSCLIPBOARD = 0x0004;
        public const uint WINSTA_CREATEDESKTOP = 0x0008;
        public const uint WINSTA_WRITEATTRIBUTES = 0x0010;
        public const uint WINSTA_ACCESSGLOBALATOMS = 0x0020;
        public const uint WINSTA_EXITWINDOWS = 0x0040;
        public const uint WINSTA_ENUMERATE = 0x0100;
        public const uint WINSTA_READSCREEN = 0x0200;
        public const uint WINSTA_ALL_ACCESS = 0x37F;
        public const uint WINSTA_MIN_START =
            WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_WRITEATTRIBUTES |
            WINSTA_ACCESSGLOBALATOMS | WINSTA_ENUMERATE;

        public const uint DESKTOP_READOBJECTS = 0x0001;
        public const uint DESKTOP_CREATEWINDOW = 0x0002;
        public const uint DESKTOP_CREATEMENU = 0x0004;
        public const uint DESKTOP_HOOKCONTROL = 0x0008;
        public const uint DESKTOP_JOURNALRECORD = 0x0010;
        public const uint DESKTOP_JOURNALPLAYBACK = 0x0020;
        public const uint DESKTOP_ENUMERATE = 0x0040;
        public const uint DESKTOP_WRITEOBJECTS = 0x0080;
        public const uint DESKTOP_SWITCHDESKTOP = 0x0100;
        public const uint DESKTOP_ALL =
            DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
            DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
            DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
            STANDARD_RIGHTS_REQUIRED;
        public const uint DESKTOP_MIN_START =
            DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
            DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS;

        public const uint CWF_CREATE_ONLY = 0x00000001;
        public const int UOI_NAME = 2;
        public const int GRANT_ACCESS = 1;
        public const int TRUSTEE_IS_SID = 0;
        public const int TRUSTEE_IS_UNKNOWN = 0;
        public const uint OBJECT_INHERIT_ACE = 0x1;
        public const uint CONTAINER_INHERIT_ACE = 0x2;
        public const int SE_FILE_OBJECT = 1;
        public const int SE_WINDOW_OBJECT = 7;
        public const uint DACL_SECURITY_INFORMATION = 0x00000004;
        public const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        public const uint GROUP_SECURITY_INFORMATION = 0x00000002;
        public const uint SDDL_REVISION_1 = 1;

        public const int CF_UNICODETEXT = 13;
        public const uint GMEM_MOVEABLE = 0x0002;
        public const uint SRCCOPY = 0x00CC0020;
        public const uint WM_PAINT = 0x000F;
        public const uint WM_DESTROY = 0x0002;
        public const uint WM_CLOSE = 0x0010;
        public const uint PM_REMOVE = 1;
        public const uint QS_ALLINPUT = 0x04FF;
        public const uint WS_POPUP = 0x80000000;
        public const uint WS_VISIBLE = 0x10000000;
        public const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
        public const int CW_USEDEFAULT = unchecked((int)0x80000000);
        public const uint EVENT_MODIFY_STATE = 0x0002;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        public static int HRESULT_FROM_WIN32(int x)
        {
            return unchecked((int)0x80070000) | (x & 0xFFFF);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_CAPABILITIES
        {
            public IntPtr AppContainerSid;
            public IntPtr Capabilities;
            public uint CapabilityCount;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public uint TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_LINKED_TOKEN
        {
            public IntPtr LinkedToken;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_APPCONTAINER_INFORMATION
        {
            public IntPtr TokenAppContainer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
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
        public struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_UI_RESTRICTIONS
        {
            public uint UIRestrictionsClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint PageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TRUSTEE
        {
            public IntPtr pMultipleTrustee;
            public int MultipleTrusteeOperation;
            public int TrusteeForm;
            public int TrusteeType;
            public IntPtr ptstrName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXPLICIT_ACCESS
        {
            public uint grfAccessPermissions;
            public int grfAccessMode;
            public uint grfInheritance;
            public TRUSTEE Trustee;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int left;
            public int top;
            public int right;
            public int bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PAINTSTRUCT
        {
            public IntPtr hdc;
            public int fErase;
            public RECT rcPaint;
            public int fRestore;
            public int fIncUpdate;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] rgbReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WNDCLASS
        {
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            public IntPtr lpszMenuName;
            public IntPtr lpszClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int ptX;
            public int ptY;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct RTL_OSVERSIONINFOW
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        public delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("ntdll.dll")]
        public static extern int RtlGetVersion(ref RTL_OSVERSIONINFOW lpVersionInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CheckTokenMembership(IntPtr TokenHandle, IntPtr SidToCheck, out bool IsMember);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateWellKnownSid(int WellKnownSidType, IntPtr DomainSid, IntPtr pSid, ref uint cbSid);

        [DllImport("advapi32.dll")]
        public static extern bool EqualSid(IntPtr a, IntPtr b);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr SecurityDescriptor, uint RequestedStringSDRevision, uint SecurityInformation, out IntPtr StringSecurityDescriptor, IntPtr StringSecurityDescriptorLen);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectSecurity(IntPtr hObj, ref uint pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetUserObjectSecurity(IntPtr hObj, ref uint pSIRequested, IntPtr pSID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool PeekNamedPipe(IntPtr hNamedPipe, IntPtr lpBuffer, uint nBufferSize, IntPtr lpBytesRead, out uint lpTotalBytesAvail, IntPtr lpBytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeriveCapabilitySidsFromName(
            string CapName,
            out IntPtr CapabilityGroupSids,
            out uint CapabilityGroupSidCount,
            out IntPtr CapabilitySids,
            out uint CapabilitySidCount);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength, IntPtr lpReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsProcessInJob(IntPtr ProcessHandle, IntPtr JobHandle, out bool Result);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern int GetCurrentProcessId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME lpCreationTime, out FILETIME lpExitTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        public static long FileTimeInt64(FILETIME ft)
        {
            return ((long)ft.dwHighDateTime << 32) | (long)ft.dwLowDateTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetEvent(IntPtr hEvent);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GlobalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int CreateAppContainerProfile(
            string pszAppContainerName,
            string pszDisplayName,
            string pszDescription,
            IntPtr pCapabilities,
            uint dwCapabilityCount,
            out IntPtr ppSidAppContainerSid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int DeleteAppContainerProfile(string pszAppContainerName);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out IntPtr ppsid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int GetAppContainerFolderPath(string pszAppContainerSid, out IntPtr ppszPath);

        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr ptr);

        [DllImport("advapi32.dll")]
        public static extern IntPtr FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            out IntPtr SecurityDescriptor,
            IntPtr SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetSecurityInfo(
            IntPtr handle,
            int ObjectType,
            uint SecurityInfo,
            IntPtr ppsidOwner,
            IntPtr ppsidGroup,
            out IntPtr ppDacl,
            IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetSecurityInfo(
            IntPtr handle,
            int ObjectType,
            uint SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint SetEntriesInAcl(
            uint cCountOfExplicitEntries,
            [In] EXPLICIT_ACCESS[] pListOfExplicitEntries,
            IntPtr OldAcl,
            out IntPtr NewAcl);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateWindowStation(string lpwinsta, uint dwFlags, uint dwDesiredAccess, IntPtr lpsa);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetProcessWindowStation(IntPtr hWinSta);

        [DllImport("user32.dll")]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice, IntPtr pDevmode, uint dwFlags, uint dwDesiredAccess, IntPtr lpsa);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        public static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetUserObjectInformationW", ExactSpelling = true, SetLastError = true)]
        public static extern bool GetUserObjectInformationW(IntPtr hObj, int nIndex, IntPtr pvInfo, uint nLength, out uint lpnLengthNeeded);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ushort RegisterClass(ref WNDCLASS lpWndClass);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateWindowEx(
            uint dwExStyle,
            string lpClassName,
            string lpWindowName,
            uint dwStyle,
            int x,
            int y,
            int nWidth,
            int nHeight,
            IntPtr hWndParent,
            IntPtr hMenu,
            IntPtr hInstance,
            IntPtr lpParam);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        public static extern bool UpdateWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr DefWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern void PostQuitMessage(int nExitCode);

        [DllImport("user32.dll")]
        public static extern uint MsgWaitForMultipleObjects(uint nCount, IntPtr[] pHandles, bool bWaitAll, uint dwMilliseconds, uint dwWakeMask);

        [DllImport("user32.dll")]
        public static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        public static extern IntPtr BeginPaint(IntPtr hWnd, out PAINTSTRUCT lpPaint);

        [DllImport("user32.dll")]
        public static extern bool EndPaint(IntPtr hWnd, ref PAINTSTRUCT lpPaint);

        [DllImport("user32.dll")]
        public static extern int FillRect(IntPtr hDC, ref RECT lprc, IntPtr hbr);

        [DllImport("user32.dll")]
        public static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("user32.dll")]
        public static extern bool IsClipboardFormatAvailable(uint format);

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateSolidBrush(uint color);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

        [DllImport("gdi32.dll")]
        public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

        [DllImport("gdi32.dll")]
        public static extern bool DeleteObject(IntPtr hObject);

        [DllImport("gdi32.dll")]
        public static extern bool DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);

        [DllImport("gdi32.dll")]
        public static extern uint GetPixel(IntPtr hdc, int nXPos, int nYPos);

        public static uint Rgb(int r, int g, int b)
        {
            return (uint)(r | (g << 8) | (b << 16));
        }

        public static bool TrySidToString(IntPtr sid, out string text)
        {
            text = "";
            IntPtr p;
            if (!ConvertSidToStringSid(sid, out p) || p == IntPtr.Zero)
            {
                return false;
            }
            try
            {
                text = Marshal.PtrToStringUni(p);
                return !string.IsNullOrEmpty(text);
            }
            finally
            {
                LocalFree(p);
            }
        }

        public static string TryGetAppContainerFolder(string sidText)
        {
            if (string.IsNullOrEmpty(sidText))
            {
                return null;
            }
            IntPtr p;
            int hr = GetAppContainerFolderPath(sidText, out p);
            if (hr != 0 || p == IntPtr.Zero)
            {
                return null;
            }
            try
            {
                return Marshal.PtrToStringUni(p);
            }
            finally
            {
                CoTaskMemFree(p);
            }
        }

        public static bool TryGetUserObjectName(IntPtr handle, out string name)
        {
            name = "unknown";
            if (handle == IntPtr.Zero)
            {
                return false;
            }
            uint needed;
            Native.GetUserObjectInformationW(handle, UOI_NAME, IntPtr.Zero, 0, out needed);
            int err = Marshal.GetLastWin32Error();
            if (needed == 0 || needed > 4096)
            {
                return false;
            }
            if (err != 0 && err != ERROR_INSUFFICIENT_BUFFER && needed < 2)
            {
                return false;
            }
            IntPtr buf = Marshal.AllocHGlobal((int)needed);
            try
            {
                uint needed2;
                if (!Native.GetUserObjectInformationW(handle, UOI_NAME, buf, needed, out needed2))
                {
                    return false;
                }
                if (needed2 < 2 || needed2 > needed || (needed2 % 2) != 0)
                {
                    return false;
                }
                string s = Marshal.PtrToStringUni(buf, (int)needed2 / 2);
                if (string.IsNullOrEmpty(s))
                {
                    return false;
                }
                name = s.TrimEnd('\0');
                if (string.IsNullOrEmpty(name))
                {
                    name = "unknown";
                    return false;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        public static string GetUserObjectName(IntPtr handle)
        {
            string name;
            if (!TryGetUserObjectName(handle, out name))
            {
                return "unknown";
            }
            return name;
        }

        public static bool IsWinSta0Name(string name)
        {
            return string.Equals(name, "WinSta0", StringComparison.OrdinalIgnoreCase);
        }

        public static uint GrantSidOnHandle(IntPtr handle, int objectType, IntPtr sid, uint access)
        {
            IntPtr pDacl;
            IntPtr pSd;
            uint g = GetSecurityInfo(handle, objectType, DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, out pDacl, IntPtr.Zero, out pSd);
            if (g != 0)
            {
                return g;
            }
            EXPLICIT_ACCESS[] ea = new EXPLICIT_ACCESS[1];
            ea[0].grfAccessPermissions = access;
            ea[0].grfAccessMode = GRANT_ACCESS;
            ea[0].grfInheritance = 0;
            ea[0].Trustee.pMultipleTrustee = IntPtr.Zero;
            ea[0].Trustee.MultipleTrusteeOperation = 0;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            ea[0].Trustee.ptstrName = sid;
            IntPtr newAcl;
            uint s = SetEntriesInAcl(1, ea, pDacl, out newAcl);
            if (s != 0)
            {
                if (pSd != IntPtr.Zero)
                {
                    LocalFree(pSd);
                }
                return s;
            }
            uint set = SetSecurityInfo(handle, objectType, DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, newAcl, IntPtr.Zero);
            if (newAcl != IntPtr.Zero)
            {
                LocalFree(newAcl);
            }
            if (pSd != IntPtr.Zero)
            {
                LocalFree(pSd);
            }
            return set;
        }

        public static bool TryReadUserObjectSddl(IntPtr handle, out string sddl, out string error)
        {
            sddl = "";
            error = "";
            if (handle == IntPtr.Zero)
            {
                error = "null_handle";
                return false;
            }
            uint si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
            uint needed;
            GetUserObjectSecurity(handle, ref si, IntPtr.Zero, 0, out needed);
            if (needed == 0 || needed > 65536)
            {
                error = "GetUserObjectSecurity size win32=" + Marshal.GetLastWin32Error() + " needed=" + needed;
                return false;
            }
            IntPtr sd = Marshal.AllocHGlobal((int)needed);
            try
            {
                uint needed2;
                si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                    DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
                if (!GetUserObjectSecurity(handle, ref si, sd, needed, out needed2))
                {
                    error = "GetUserObjectSecurity win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                IntPtr str;
                uint info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                    DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
                if (!ConvertSecurityDescriptorToStringSecurityDescriptor(sd, SDDL_REVISION_1, info, out str, IntPtr.Zero) ||
                    str == IntPtr.Zero)
                {
                    error = "ConvertSecurityDescriptorToStringSecurityDescriptor win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                try
                {
                    sddl = Marshal.PtrToStringUni(str) ?? "";
                    if (string.IsNullOrEmpty(sddl))
                    {
                        error = "empty_sddl";
                        return false;
                    }
                    return true;
                }
                finally
                {
                    LocalFree(str);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(sd);
            }
        }

        public static void RtlZero(IntPtr p, int n)
        {
            byte[] z = new byte[n];
            Marshal.Copy(z, 0, p, n);
        }
    }
}
