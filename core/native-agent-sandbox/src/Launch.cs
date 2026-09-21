using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NativeAgentSandbox
{
    internal enum SandboxLevel
    {
        Production = 0,
        InternalLpac = 1,
        InternalAppContainer = 2,
        JobUiOnly = 3,
        Unconstrained = 4
    }

    internal sealed class LaunchRequest
    {
        public GrokSessionSpec Grok;
        public ControllerChannel Channel;
        public SandboxLevel Level = SandboxLevel.Production;
        public string NetworkMode = "offline";
        public string Executable;
        public string[] Arguments = new string[0];
        public string WorkingDirectory;
        public Dictionary<string, string> ExtraEnv = new Dictionary<string, string>(StringComparer.Ordinal);
        public int DeadlineMs = Constants.ProductionDefaultDeadlineMs;
        public string StdoutPath;
        public string StderrPath;
        public string Desktop;
        public bool UsePrivateDesktop = true;
        public bool UseUiLimits = true;
        public uint UiLimitFlags = Constants.RequiredUiFlags;
        public bool CopyExeToProfile = true;
        public bool DeleteProfileAfter = true;
        public bool RequirePrivateDesktop = true;
        public bool WaitForExit = true;
        public bool UseStdPipes = true;
        public bool InjectJobAssignFailure;
        public bool UseRegistryReadCapability;
        public AppContainerSession ExistingAc;
        // Internal ownership transfer only; never accepted by Config.FromJson.
        public Nmzp.NativeEgressFilter.OwnedNetworkJobLease ExistingLease;
        public IntPtr PayloadToken;
        public IntPtr ImpersonationToken;
        public SyntheticStation OwnedStation;
        public bool PrivilegedSession;
        public string SessionDirectory;
        public bool ExclusiveJobDacl;
        public int GatewayPort;
        public int ControllerPid;
        public long ControllerCreationTime;
        public Nmzp.NativeEgressFilter.IFilterWorld FilterWorld;
        public bool SkipPrivateDesktopForBrokeredTest;
        public bool InjectSkipJobAssign;
        public System.Action AfterBindHook;
    }

    internal sealed class LaunchResult
    {
        public bool Ok;
        public string ErrorCode = "";
        public string Error = "";
        public int ExitCode = -1;
        public int Win32;
        public int Pid;
        public bool InJob;
        public bool DegradedToNormalProcess;
        public string ProfileName = "";
        public string AppContainerSid = "";
        public string AppContainerKind = "";
        public bool LpacOptOut;
        public string ProfileFolder = "";
        public string StagingApp = "";
        public string StagingWorkspace = "";
        public string Desktop = "";
        public string WindowStation = "";
        public bool KillOnCloseSet;
        public bool UiLimitsSet;
        public uint UiLimitsFlags;
        public List<string> UiLimitNames = new List<string>();
        public bool DisplaySettingsIsNotAntiScreenshot = true;
        public bool HandleWhitelistExplicit;
        public bool JobHandleNotInherited = true;
        public string EnvironmentMode = "allowlist";
        public int ElapsedMs;
        public string Stdout = "";
        public string Stderr = "";
        public bool StdoutTruncated;
        public bool StderrTruncated;
        public bool DrainIncomplete;
        public JVal Extra = JVal.Obj();

        public JVal ToJson()
        {
            JVal o = JVal.Obj();
            o.Map["ok"] = JVal.Bool(Ok);
            o.Map["error_code"] = JVal.Str(ErrorCode);
            o.Map["error"] = JVal.Str(Error);
            o.Map["exit_code"] = JVal.Num(ExitCode);
            o.Map["win32"] = JVal.Num(Win32);
            o.Map["pid"] = JVal.Num(Pid);
            o.Map["in_job"] = JVal.Bool(InJob);
            o.Map["degraded_to_normal_process"] = JVal.Bool(DegradedToNormalProcess);
            o.Map["profile_name"] = JVal.Str(ProfileName);
            o.Map["appcontainer_sid_present"] = JVal.Bool(!string.IsNullOrEmpty(AppContainerSid));
            o.Map["appcontainer_sid_len"] = JVal.Num(AppContainerSid == null ? 0 : AppContainerSid.Length);
            o.Map["appcontainer_kind"] = JVal.Str(AppContainerKind);
            o.Map["lpac_all_application_packages_opt_out"] = JVal.Bool(LpacOptOut);
            o.Map["profile_folder"] = JVal.Str(ProfileFolder);
            o.Map["staging_app"] = JVal.Str(StagingApp);
            o.Map["staging_workspace"] = JVal.Str(StagingWorkspace);
            o.Map["desktop"] = JVal.Str(Desktop);
            o.Map["window_station"] = JVal.Str(WindowStation);
            o.Map["kill_on_close_set"] = JVal.Bool(KillOnCloseSet);
            o.Map["ui_limits_set"] = JVal.Bool(UiLimitsSet);
            o.Map["ui_limits_flags"] = JVal.Num(UiLimitsFlags);
            JVal names = JVal.Arr();
            for (int i = 0; i < UiLimitNames.Count; i++)
            {
                names.Items.Add(JVal.Str(UiLimitNames[i]));
            }
            o.Map["ui_limits_flag_names"] = names;
            o.Map["displaysettings_is_not_anti_screenshot"] = JVal.Bool(DisplaySettingsIsNotAntiScreenshot);
            o.Map["handle_whitelist_explicit"] = JVal.Bool(HandleWhitelistExplicit);
            o.Map["job_handle_not_inherited"] = JVal.Bool(JobHandleNotInherited);
            o.Map["environment_mode"] = JVal.Str(EnvironmentMode);
            o.Map["elapsed_ms"] = JVal.Num(ElapsedMs);
            o.Map["stdout"] = JVal.Str(Stdout ?? "");
            o.Map["stderr"] = JVal.Str(Stderr ?? "");
            o.Map["stdout_truncated"] = JVal.Bool(StdoutTruncated);
            o.Map["stderr_truncated"] = JVal.Bool(StderrTruncated);
            o.Map["drain_incomplete"] = JVal.Bool(DrainIncomplete);
            if (Extra != null && Extra.Kind == "obj")
            {
                o.Map["extra"] = Extra;
            }
            return o;
        }

        public static LaunchResult Fail(string code, string error, int win32)
        {
            LaunchResult r = new LaunchResult();
            r.Ok = false;
            r.ErrorCode = code;
            r.Error = error;
            r.Win32 = win32;
            r.DegradedToNormalProcess = false;
            r.ExitCode = 1;
            return r;
        }
    }

    internal static class NetworkFilterBroker
    {
        public static bool RealApplyEnabledThisBuild
        {
            get {
#if NMZP_ENABLE_OWNED_WFP
                return true;
#else
                return false;
#endif
            }
        }
    }

    internal static class Config
    {
        public static LaunchRequest FromJson(string json)
        {
            JVal root = Json.Parse(json);
            if (root == null || root.Kind != "obj")
            {
                throw new InvalidOperationException("config must be a json object");
            }
            if (root.Get("desktop") != null)
            {
                throw new InvalidOperationException("desktop is not accepted on the production schema");
            }
            if (root.Get("token_handle") != null || root.Get("pid") != null || root.Get("process_id") != null ||
                root.Get("token") != null || root.Get("impersonation_token") != null)
            {
                throw new InvalidOperationException("external token/pid is not accepted");
            }
            HashSet<string> allowed = new HashSet<string>(new string[] {
                "appcontainer_kind", "network_mode", "executable", "working_directory",
                "stdout_path", "stderr_path", "deadline_ms", "arguments", "environment",
                "ui_restrictions", "gateway_port", "controller_pid", "controller_creation_time", "grok_session"
            }, StringComparer.Ordinal);
            foreach (string key in root.Map.Keys)
                if (!allowed.Contains(key)) throw new InvalidOperationException("unknown production config field");
            string kind = Val(root, "appcontainer_kind", "lpac");
            if (!string.Equals(kind, "lpac", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("production appcontainer_kind must be lpac");
            }
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Production;
            req.NetworkMode = Val(root, "network_mode", "offline");
            req.Executable = Val(root, "executable", "");
            req.WorkingDirectory = Val(root, "working_directory", "");
            req.StdoutPath = Val(root, "stdout_path", "");
            req.StderrPath = Val(root, "stderr_path", "");
            req.Desktop = "";
            req.UsePrivateDesktop = true;
            req.RequirePrivateDesktop = true;
            req.UseUiLimits = true;
            req.UseStdPipes = true;
            req.UiLimitFlags = Constants.RequiredUiFlags;
            req.DeadlineMs = root.Get("deadline_ms") != null ? root.Get("deadline_ms").AsInt(Constants.ProductionDefaultDeadlineMs) : Constants.ProductionDefaultDeadlineMs;
            if (req.DeadlineMs < 1000)
            {
                req.DeadlineMs = 1000;
            }
            if (req.DeadlineMs > Constants.ProductionMaxDeadlineMs)
            {
                req.DeadlineMs = Constants.ProductionMaxDeadlineMs;
            }
            JVal args = root.Get("arguments");
            if (args != null && args.Kind == "arr")
            {
                List<string> list = new List<string>();
                for (int i = 0; i < args.Items.Count; i++)
                {
                    list.Add(args.Items[i].AsString(""));
                }
                req.Arguments = list.ToArray();
            }
            JVal extra = root.Get("environment");
            if (extra != null && extra.Kind == "obj")
            {
                foreach (KeyValuePair<string, JVal> kv in extra.Map)
                {
                    ValidateExtraKey(kv.Key, kv.Value.AsString(""));
                    req.ExtraEnv[kv.Key] = kv.Value.AsString("");
                }
            }
            JVal ui = root.Get("ui_restrictions");
            if (ui != null && ui.Kind == "arr")
            {
                uint flags = Constants.RequiredUiFlags;
                for (int i = 0; i < ui.Items.Count; i++)
                {
                    flags |= ParseUiFlag(ui.Items[i].AsString(""));
                }
                req.UiLimitFlags = flags | Constants.RequiredUiFlags;
            }
            if (string.Equals(req.NetworkMode, "brokered", StringComparison.OrdinalIgnoreCase))
            {
                req.GatewayPort = root.Get("gateway_port") != null ? root.Get("gateway_port").AsInt(0) : 0;
                req.ControllerPid = root.Get("controller_pid") != null ? root.Get("controller_pid").AsInt(0) : 0;
                JVal ctValue = root.Get("controller_creation_time");
                if (ctValue == null || ctValue.Kind != "str")
                    throw new InvalidOperationException("controller_creation_time must be decimal string FILETIME");
                string ct = ctValue.AsString("");
                long parsed;
                if (!System.Text.RegularExpressions.Regex.IsMatch(ct, "^[0-9]{1,19}$") ||
                    !long.TryParse(ct, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out parsed) || parsed <= 0)
                {
                    throw new InvalidOperationException("brokered mode requires controller_creation_time");
                }
                req.ControllerCreationTime = parsed;
                if (req.GatewayPort < 1 || req.GatewayPort > 65535 || req.ControllerPid <= 0)
                {
                    throw new InvalidOperationException("brokered mode requires gateway_port and controller_pid");
                }
            }
            if (root.Get("grok_session") != null) {
                if (req.NetworkMode != "brokered" || req.Arguments.Length != 0 || req.ExtraEnv.Count != 0 || req.StdoutPath.Length != 0 || req.StderrPath.Length != 0)
                    throw new InvalidOperationException("grok session requires brokered mode and fixed arguments/environment/stdio");
                req.Grok = GrokSessionSpec.Parse(root.Get("grok_session"));
            }
            return req;
        }

        static void ValidateExtraKey(string key, string value)
        {
            if (string.IsNullOrEmpty(key) || key.Length > 64 || key.IndexOf('=') >= 0 || key.IndexOf('\0') >= 0)
            {
                throw new InvalidOperationException("invalid environment key");
            }
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] < 32)
                {
                    throw new InvalidOperationException("invalid environment key");
                }
            }
            if (value == null)
            {
                value = "";
            }
            if (value.Length > 4096 || value.IndexOf('\0') >= 0)
            {
                throw new InvalidOperationException("invalid environment value");
            }
            if (EnvBlock.IsReserved(key))
            {
                throw new InvalidOperationException("cannot set reserved environment key " + key);
            }
        }

        static string Val(JVal root, string key, string fallback)
        {
            JVal v = root.Get(key);
            if (v == null)
            {
                return fallback;
            }
            return v.AsString(fallback);
        }

        static uint ParseUiFlag(string name)
        {
            if (string.Equals(name, "HANDLES", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_HANDLES;
            if (string.Equals(name, "READCLIPBOARD", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_READCLIPBOARD;
            if (string.Equals(name, "WRITECLIPBOARD", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
            if (string.Equals(name, "DESKTOP", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_DESKTOP;
            if (string.Equals(name, "DISPLAYSETTINGS", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
            if (string.Equals(name, "SYSTEMPARAMETERS", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
            if (string.Equals(name, "GLOBALATOMS", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_GLOBALATOMS;
            if (string.Equals(name, "EXITWINDOWS", StringComparison.OrdinalIgnoreCase)) return Native.JOB_OBJECT_UILIMIT_EXITWINDOWS;
            return 0;
        }
    }

    internal static class EnvBlock
    {
        public static readonly string[] ParentAllowlist = new string[]
        {
            "SystemRoot", "SystemDrive", "windir", "OS",
            "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
            "PATHEXT"
        };

        static readonly string[] Reserved = new string[]
        {
            "SystemRoot", "SystemDrive", "windir", "PATH", "TEMP", "TMP",
            "LOCALAPPDATA", "USERPROFILE", "APPDATA", "HOMEDRIVE", "HOMEPATH",
            "HOME", "GROK_HOME", "GROK_CLI_CHAT_PROXY_BASE_URL", "ComSpec",
            "NMZP_SANDBOX"
        };

        public static bool IsReserved(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                return true;
            }
            for (int i = 0; i < Reserved.Length; i++)
            {
                if (string.Equals(Reserved[i], key, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public static IntPtr Build(LaunchRequest req, string staging, string profileFolder, out string detail)
        {
            Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < ParentAllowlist.Length; i++)
            {
                string k = ParentAllowlist[i];
                string v = Environment.GetEnvironmentVariable(k);
                if (v != null)
                {
                    map[k] = v;
                }
            }
            StringBuilder skipped = new StringBuilder();
            if (req.ExtraEnv != null)
            {
                foreach (KeyValuePair<string, string> kv in req.ExtraEnv)
                {
                    if (IsReserved(kv.Key))
                    {
                        skipped.Append(kv.Key).Append(":reserved;");
                        continue;
                    }
                    if (string.IsNullOrEmpty(kv.Key) || kv.Key.IndexOf('=') >= 0 || kv.Key.IndexOf('\0') >= 0)
                    {
                        skipped.Append(kv.Key).Append(":bad;");
                        continue;
                    }
                    map[kv.Key] = kv.Value ?? "";
                }
            }
            string sys = Environment.GetEnvironmentVariable("SystemRoot");
            if (string.IsNullOrEmpty(sys))
            {
                sys = @"C:\Windows";
            }
            string path = Path.Combine(sys, "System32") + ";" + sys;
            if (!string.IsNullOrEmpty(staging) && Directory.Exists(staging))
            {
                path = staging + ";" + path;
            }
            string home = profileFolder;
            if (string.IsNullOrEmpty(home))
            {
                home = staging;
            }
            if (string.IsNullOrEmpty(home))
            {
                home = Path.GetTempPath();
            }
            string tdir = Path.Combine(home, "Temp");
            try { Directory.CreateDirectory(tdir); }
            catch { }
            map["SystemRoot"] = sys;
            map["SystemDrive"] = Environment.GetEnvironmentVariable("SystemDrive") ?? Path.GetPathRoot(sys);
            map["windir"] = sys;
            map["PATH"] = path;
            map["TEMP"] = tdir;
            map["TMP"] = tdir;
            map["LOCALAPPDATA"] = home;
            map["USERPROFILE"] = home;
            map["GROK_HOME"] = home;
            map["HOME"] = home;
            map["APPDATA"] = home;
            map["NMZP_SANDBOX"] = "1";
            map["ComSpec"] = Path.Combine(sys, "System32", "cmd.exe");
            detail = "keys=" + map.Count + " skipped=" + skipped.ToString();
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kv in map)
            {
                sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
            }
            sb.Append('\0');
            byte[] bytes = Encoding.Unicode.GetBytes(sb.ToString());
            IntPtr p = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, p, bytes.Length);
            return p;
        }
    }

    internal static class JobObject
    {
        public static IntPtr CreateNonInheritable(string name, out int win32)
        {
            return CreateNonInheritable(name, null, out win32);
        }

        public static IntPtr CreateNonInheritable(string name, string sddl, out int win32)
        {
            Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = 0;
            IntPtr sd = IntPtr.Zero;
            if (!string.IsNullOrEmpty(sddl))
            {
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, Native.SDDL_REVISION_1, out sd, IntPtr.Zero) ||
                    sd == IntPtr.Zero)
                {
                    win32 = Marshal.GetLastWin32Error();
                    return IntPtr.Zero;
                }
                sa.lpSecurityDescriptor = sd;
            }
            IntPtr psa = Marshal.AllocHGlobal(sa.nLength);
            try
            {
                Marshal.StructureToPtr(sa, psa, false);
                IntPtr job = Native.CreateJobObject(psa, name);
                win32 = Marshal.GetLastWin32Error();
                if (job == IntPtr.Zero)
                {
                    return IntPtr.Zero;
                }
                if (!string.IsNullOrEmpty(name) && win32 == Native.ERROR_ALREADY_EXISTS)
                {
                    Native.CloseHandle(job);
                    return IntPtr.Zero;
                }
                Native.SetHandleInformation(job, Native.HANDLE_FLAG_INHERIT, 0);
                win32 = 0;
                return job;
            }
            finally
            {
                Marshal.FreeHGlobal(psa);
                if (sd != IntPtr.Zero)
                {
                    Native.LocalFree(sd);
                }
            }
        }

        public static bool SetKillOnClose(IntPtr job, out string detail)
        {
            Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr mem = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, mem, false);
                if (!Native.SetInformationJobObject(job, Native.JobObjectExtendedLimitInformation, mem, (uint)size))
                {
                    detail = "SetInformationJobObject extended win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                Native.RtlZero(mem, size);
                if (!Native.QueryInformationJobObject(job, Native.JobObjectExtendedLimitInformation, mem, (uint)size, IntPtr.Zero))
                {
                    detail = "QueryInformationJobObject extended win32=" + Marshal.GetLastWin32Error() + "; kill_on_close not verified";
                    return false;
                }
                Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION q =
                    (Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)Marshal.PtrToStructure(mem, typeof(Native.JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                if ((q.BasicLimitInformation.LimitFlags & Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0)
                {
                    detail = "kill_on_close bit missing after query flags=0x" + q.BasicLimitInformation.LimitFlags.ToString("X");
                    return false;
                }
                detail = "verified sizeof=" + size;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        public static bool SetUiLimits(IntPtr job, uint flags, out uint actual, out string detail)
        {
            actual = 0;
            Native.JOBOBJECT_BASIC_UI_RESTRICTIONS ui = new Native.JOBOBJECT_BASIC_UI_RESTRICTIONS();
            ui.UIRestrictionsClass = flags;
            int size = Marshal.SizeOf(typeof(Native.JOBOBJECT_BASIC_UI_RESTRICTIONS));
            IntPtr mem = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(ui, mem, false);
                if (!Native.SetInformationJobObject(job, Native.JobObjectBasicUIRestrictions, mem, (uint)size))
                {
                    detail = "SetInformationJobObject ui win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                Native.RtlZero(mem, size);
                if (!Native.QueryInformationJobObject(job, Native.JobObjectBasicUIRestrictions, mem, (uint)size, IntPtr.Zero))
                {
                    detail = "QueryInformationJobObject ui win32=" + Marshal.GetLastWin32Error() + "; not verified";
                    actual = 0;
                    return false;
                }
                Native.JOBOBJECT_BASIC_UI_RESTRICTIONS q =
                    (Native.JOBOBJECT_BASIC_UI_RESTRICTIONS)Marshal.PtrToStructure(mem, typeof(Native.JOBOBJECT_BASIC_UI_RESTRICTIONS));
                actual = q.UIRestrictionsClass;
                if ((actual & flags) != flags)
                {
                    detail = "ui flags incomplete queried=0x" + actual.ToString("X") + " requested=0x" + flags.ToString("X");
                    return false;
                }
                detail = "verified flags=0x" + actual.ToString("X");
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        public static bool TryGetActiveProcesses(IntPtr job, out uint active)
        {
            active = uint.MaxValue;
            if (job == IntPtr.Zero)
            {
                return false;
            }
            int size = Marshal.SizeOf(typeof(Native.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr mem = Marshal.AllocHGlobal(size);
            try
            {
                Native.RtlZero(mem, size);
                if (!Native.QueryInformationJobObject(job, Native.JobObjectBasicAccountingInformation, mem, (uint)size, IntPtr.Zero))
                {
                    return false;
                }
                Native.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION q =
                    (Native.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(mem, typeof(Native.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
                active = q.ActiveProcesses;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        public static List<string> FlagNames(uint flags)
        {
            List<string> names = new List<string>();
            if ((flags & Native.JOB_OBJECT_UILIMIT_HANDLES) != 0) names.Add("HANDLES");
            if ((flags & Native.JOB_OBJECT_UILIMIT_READCLIPBOARD) != 0) names.Add("READCLIPBOARD");
            if ((flags & Native.JOB_OBJECT_UILIMIT_WRITECLIPBOARD) != 0) names.Add("WRITECLIPBOARD");
            if ((flags & Native.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS) != 0) names.Add("DISPLAYSETTINGS");
            if ((flags & Native.JOB_OBJECT_UILIMIT_DESKTOP) != 0) names.Add("DESKTOP");
            if ((flags & Native.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS) != 0) names.Add("SYSTEMPARAMETERS");
            if ((flags & Native.JOB_OBJECT_UILIMIT_GLOBALATOMS) != 0) names.Add("GLOBALATOMS");
            if ((flags & Native.JOB_OBJECT_UILIMIT_EXITWINDOWS) != 0) names.Add("EXITWINDOWS");
            return names;
        }
    }

    internal sealed class AppContainerSession : IDisposable
    {
        public string Name;
        public IntPtr Sid;
        public string SidText;
        public string Folder;
        public bool Created;
        public bool Borrowed;

        public void Dispose()
        {
            if (Sid != IntPtr.Zero)
            {
                Native.FreeSid(Sid);
                Sid = IntPtr.Zero;
            }
        }

        public int DeleteIfOwned()
        {
            if (Borrowed || !Created || !TextUtil.IsSafeProfileName(Name))
            {
                return 0;
            }
            Thread.Sleep(200);
            int hr = Native.DeleteAppContainerProfile(Name);
            if (hr != 0)
            {
                Thread.Sleep(400);
                hr = Native.DeleteAppContainerProfile(Name);
            }
            return hr;
        }

        public static AppContainerSession CreateUnique(out string error, out int win32)
        {
            error = "";
            win32 = 0;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                AppContainerSession s = new AppContainerSession();
                s.Name = Constants.ProfilePrefix + TextUtil.NewNonce().Substring(0, 16);
                IntPtr sid;
                int hr = Native.CreateAppContainerProfile(s.Name, s.Name, Constants.ComponentName, IntPtr.Zero, 0, out sid);
                if (hr == Native.HRESULT_FROM_WIN32(Native.ERROR_ALREADY_EXISTS))
                {
                    continue;
                }
                if (hr != 0 || sid == IntPtr.Zero)
                {
                    error = "CreateAppContainerProfile hr=0x" + hr.ToString("X8");
                    win32 = hr;
                    return null;
                }
                s.Sid = sid;
                s.Created = true;
                Native.TrySidToString(sid, out s.SidText);
                s.Folder = Native.TryGetAppContainerFolder(s.SidText);
                return s;
            }
            error = "profile_collision";
            win32 = Native.ERROR_ALREADY_EXISTS;
            return null;
        }

        public static AppContainerSession BorrowFromLease(Nmzp.NativeEgressFilter.OwnedNetworkJobLease lease, out string error)
        {
            error = "";
            if (lease == null || string.IsNullOrEmpty(lease.ProfileName) || string.IsNullOrEmpty(lease.PackageSid) ||
                string.IsNullOrEmpty(lease.ProfileFolder))
            {
                error = "lease_identity_missing";
                return null;
            }
            IntPtr sid;
            if (!Native.ConvertStringSidToSid(lease.PackageSid, out sid) || sid == IntPtr.Zero)
            {
                error = "ConvertStringSidToSid win32=" + Marshal.GetLastWin32Error();
                return null;
            }
            AppContainerSession s = new AppContainerSession();
            s.Name = lease.ProfileName;
            s.SidText = lease.PackageSid;
            s.Folder = lease.ProfileFolder;
            s.Sid = sid;
            s.Created = false;
            s.Borrowed = true;
            return s;
        }
    }

    internal sealed class CapabilitySet : IDisposable
    {
        public IntPtr Array;
        public uint Count;
        IntPtr sidList;
        uint sidCount;
        IntPtr groupList;
        uint groupCount;
        bool disposed;

        public static CapabilitySet TryRegistryRead()
        {
            IntPtr groups;
            IntPtr sids;
            uint gc;
            uint sc;
            if (!Native.DeriveCapabilitySidsFromName("registryRead", out groups, out gc, out sids, out sc) || sc == 0 || sids == IntPtr.Zero)
            {
                return null;
            }
            CapabilitySet c = new CapabilitySet();
            c.sidList = sids;
            c.sidCount = sc;
            c.groupList = groups;
            c.groupCount = gc;
            IntPtr first = Marshal.ReadIntPtr(sids, 0);
            int sz = Marshal.SizeOf(typeof(Native.SID_AND_ATTRIBUTES));
            c.Array = Marshal.AllocHGlobal(sz);
            Native.SID_AND_ATTRIBUTES sa = new Native.SID_AND_ATTRIBUTES();
            sa.Sid = first;
            sa.Attributes = Native.SE_GROUP_ENABLED;
            Marshal.StructureToPtr(sa, c.Array, false);
            c.Count = 1;
            return c;
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (Array != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Array);
                Array = IntPtr.Zero;
            }
            FreeSidArray(sidList, sidCount);
            FreeSidArray(groupList, groupCount);
            sidList = IntPtr.Zero;
            groupList = IntPtr.Zero;
        }

        static void FreeSidArray(IntPtr list, uint count)
        {
            if (list == IntPtr.Zero)
            {
                return;
            }
            for (uint i = 0; i < count; i++)
            {
                IntPtr sid = Marshal.ReadIntPtr(list, (int)i * IntPtr.Size);
                if (sid != IntPtr.Zero)
                {
                    Native.LocalFree(sid);
                }
            }
            Native.LocalFree(list);
        }
    }

    internal static class StdPipes
    {
        public static bool Create(ChildSession sess, out string error)
        {
            error = "";
            Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
            sa.bInheritHandle = 1;
            sa.lpSecurityDescriptor = IntPtr.Zero;
            IntPtr cIn, pIn, cOut, pOut, cErr, pErr;
            if (!Native.CreatePipe(out cIn, out pIn, ref sa, 0))
            {
                error = "stdin pipe win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            if (!Native.CreatePipe(out pOut, out cOut, ref sa, 0))
            {
                error = "stdout pipe win32=" + Marshal.GetLastWin32Error();
                Native.CloseHandle(cIn);
                Native.CloseHandle(pIn);
                return false;
            }
            if (!Native.CreatePipe(out pErr, out cErr, ref sa, 0))
            {
                error = "stderr pipe win32=" + Marshal.GetLastWin32Error();
                Native.CloseHandle(cIn);
                Native.CloseHandle(pIn);
                Native.CloseHandle(cOut);
                Native.CloseHandle(pOut);
                return false;
            }
            Native.SetHandleInformation(pIn, Native.HANDLE_FLAG_INHERIT, 0);
            Native.SetHandleInformation(pOut, Native.HANDLE_FLAG_INHERIT, 0);
            Native.SetHandleInformation(pErr, Native.HANDLE_FLAG_INHERIT, 0);
            Native.SetHandleInformation(cIn, Native.HANDLE_FLAG_INHERIT, Native.HANDLE_FLAG_INHERIT);
            Native.SetHandleInformation(cOut, Native.HANDLE_FLAG_INHERIT, Native.HANDLE_FLAG_INHERIT);
            Native.SetHandleInformation(cErr, Native.HANDLE_FLAG_INHERIT, Native.HANDLE_FLAG_INHERIT);
            sess.ChildStdin = cIn;
            sess.StdinWrite = pIn;
            sess.ChildStdout = cOut;
            sess.StdoutRead = pOut;
            sess.ChildStderr = cErr;
            sess.StderrRead = pErr;
            return true;
        }
    }

    internal static class ProcessCreator
    {
        public static bool CreateSuspended(
            string exe,
            string commandLine,
            string cwd,
            string desktop,
            IntPtr appContainerSid,
            bool lpac,
            IntPtr envBlock,
            IntPtr[] inheritHandles,
            IntPtr capList,
            uint capCount,
            IntPtr hStdIn,
            IntPtr hStdOut,
            IntPtr hStdErr,
            IntPtr hUserToken,
            out IntPtr hProcess,
            out IntPtr hThread,
            out int win32)
        {
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;
            win32 = 0;
            if (lpac && appContainerSid == IntPtr.Zero)
            {
                win32 = 87;
                return false;
            }

            bool hasHandleList = inheritHandles != null && inheritHandles.Length > 0;
            int attrCount = 0;
            if (hasHandleList) attrCount++;
            if (appContainerSid != IntPtr.Zero) attrCount++;
            if (lpac) attrCount++;

            IntPtr attrList = IntPtr.Zero;
            IntPtr capPtr = IntPtr.Zero;
            IntPtr policyPtr = IntPtr.Zero;
            IntPtr handleListPtr = IntPtr.Zero;
            IntPtr desktopPtr = IntPtr.Zero;
            bool attrInit = false;
            try
            {
                if (attrCount > 0)
                {
                    IntPtr size = IntPtr.Zero;
                    Native.InitializeProcThreadAttributeList(IntPtr.Zero, attrCount, 0, ref size);
                    if (size == IntPtr.Zero)
                    {
                        win32 = Marshal.GetLastWin32Error();
                        return false;
                    }
                    attrList = Marshal.AllocHGlobal(size.ToInt32());
                    Native.RtlZero(attrList, size.ToInt32());
                    if (!Native.InitializeProcThreadAttributeList(attrList, attrCount, 0, ref size))
                    {
                        win32 = Marshal.GetLastWin32Error();
                        return false;
                    }
                    attrInit = true;

                    if (hasHandleList)
                    {
                        handleListPtr = Marshal.AllocHGlobal(IntPtr.Size * inheritHandles.Length);
                        for (int i = 0; i < inheritHandles.Length; i++)
                        {
                            Marshal.WriteIntPtr(handleListPtr, i * IntPtr.Size, inheritHandles[i]);
                        }
                        if (!Native.UpdateProcThreadAttribute(
                            attrList, 0, new IntPtr(Native.PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
                            handleListPtr, new IntPtr(IntPtr.Size * inheritHandles.Length),
                            IntPtr.Zero, IntPtr.Zero))
                        {
                            win32 = Marshal.GetLastWin32Error();
                            return false;
                        }
                    }
                    if (appContainerSid != IntPtr.Zero)
                    {
                        Native.SECURITY_CAPABILITIES cap = new Native.SECURITY_CAPABILITIES();
                        cap.AppContainerSid = appContainerSid;
                        cap.Capabilities = capList;
                        cap.CapabilityCount = capCount;
                        cap.Reserved = 0;
                        capPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.SECURITY_CAPABILITIES)));
                        Marshal.StructureToPtr(cap, capPtr, false);
                        if (!Native.UpdateProcThreadAttribute(
                            attrList, 0, new IntPtr(Native.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
                            capPtr, new IntPtr(Marshal.SizeOf(typeof(Native.SECURITY_CAPABILITIES))),
                            IntPtr.Zero, IntPtr.Zero))
                        {
                            win32 = Marshal.GetLastWin32Error();
                            return false;
                        }
                    }
                    if (lpac)
                    {
                        policyPtr = Marshal.AllocHGlobal(4);
                        Marshal.WriteInt32(policyPtr, (int)Native.PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT);
                        if (!Native.UpdateProcThreadAttribute(
                            attrList, 0, new IntPtr(Native.PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY),
                            policyPtr, new IntPtr(4),
                            IntPtr.Zero, IntPtr.Zero))
                        {
                            win32 = Marshal.GetLastWin32Error();
                            return false;
                        }
                    }
                }

                Native.STARTUPINFOEX si = new Native.STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(Native.STARTUPINFOEX));
                si.StartupInfo.dwFlags = Native.STARTF_USESHOWWINDOW;
                si.StartupInfo.wShowWindow = Native.SW_HIDE;
                if (hStdIn != IntPtr.Zero || hStdOut != IntPtr.Zero || hStdErr != IntPtr.Zero)
                {
                    si.StartupInfo.dwFlags |= Native.STARTF_USESTDHANDLES;
                    si.StartupInfo.hStdInput = hStdIn;
                    si.StartupInfo.hStdOutput = hStdOut;
                    si.StartupInfo.hStdError = hStdErr;
                }
                si.lpAttributeList = attrList;
                if (!string.IsNullOrEmpty(desktop))
                {
                    desktopPtr = Marshal.StringToHGlobalUni(desktop);
                    si.StartupInfo.lpDesktop = desktopPtr;
                }

                Native.PROCESS_INFORMATION pi;
                StringBuilder cmd = new StringBuilder(commandLine);
                uint flags = Native.CREATE_SUSPENDED | Native.CREATE_NO_WINDOW | Native.CREATE_UNICODE_ENVIRONMENT;
                if (attrCount > 0)
                {
                    flags |= Native.EXTENDED_STARTUPINFO_PRESENT;
                }
                bool inherit = hasHandleList;
                bool ok;
                if (hUserToken != IntPtr.Zero)
                {
                    ok = Native.CreateProcessAsUserW(
                        hUserToken,
                        exe,
                        cmd,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        inherit,
                        flags,
                        envBlock,
                        string.IsNullOrEmpty(cwd) ? null : cwd,
                        ref si,
                        out pi);
                }
                else
                {
                    ok = Native.CreateProcess(
                        exe,
                        cmd,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        inherit,
                        flags,
                        envBlock,
                        string.IsNullOrEmpty(cwd) ? null : cwd,
                        ref si,
                        out pi);
                }
                if (!ok)
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                hProcess = pi.hProcess;
                hThread = pi.hThread;
                return true;
            }
            finally
            {
                if (attrInit)
                {
                    Native.DeleteProcThreadAttributeList(attrList);
                }
                if (attrList != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attrList);
                }
                if (capPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(capPtr);
                }
                if (policyPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(policyPtr);
                }
                if (handleListPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(handleListPtr);
                }
                if (desktopPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(desktopPtr);
                }
            }
        }
    }

    internal sealed class SyntheticStation : IDisposable
    {
        public string WinstaName;
        public string GrantedPackageSid;
        public string DeskName;
        public string Desktop;
        public IntPtr Winsta;
        public IntPtr Desk;
        bool disposed;

        public bool NewlyOwned;
        public string ErrorCode;

        public static SyntheticStation TryCreateUnnamedOwned(out string error)
        {
            error = "";
            IntPtr prevSta = Native.GetProcessWindowStation();
            IntPtr prevDesk = Native.GetThreadDesktop(Native.GetCurrentThreadId());
            string prevName = Native.GetUserObjectName(prevSta);
            IntPtr sd = IntPtr.Zero;
            IntPtr psa = IntPtr.Zero;
            SyntheticStation s = new SyntheticStation();
            s.DeskName = "d" + TextUtil.NewNonce().Substring(0, 8);
            bool switched = false;
            try
            {
                if (!TryUserOnlySd(out sd, out error))
                {
                    s.ErrorCode = "requires_admin";
                    return null;
                }
                Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = 0;
                psa = Marshal.AllocHGlobal(sa.nLength);
                Marshal.StructureToPtr(sa, psa, false);
                s.Winsta = Native.CreateWindowStation(null, Native.CWF_CREATE_ONLY,
                    Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL | Native.WRITE_DAC, psa);
                int lastErr = Marshal.GetLastWin32Error();
                if (s.Winsta == IntPtr.Zero)
                {
                    error = "CreateWindowStation(NULL,CWF_CREATE_ONLY) win32=" + lastErr +
                        " prev=" + prevName + " named_stations_require_admin_per_msdn";
                    s.ErrorCode = (lastErr == Native.ERROR_ACCESS_DENIED || lastErr == Native.ERROR_ALREADY_EXISTS)
                        ? "requires_admin" : "winsta_create";
                    s.Dispose();
                    return null;
                }
                s.WinstaName = Native.GetUserObjectName(s.Winsta);
                if (string.IsNullOrEmpty(s.WinstaName) ||
                    string.Equals(s.WinstaName, "WinSta0", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(s.WinstaName, prevName, StringComparison.OrdinalIgnoreCase))
                {
                    error = "unnamed CreateWindowStation returned existing station '" + s.WinstaName + "'; refused";
                    s.ErrorCode = "requires_admin";
                    Native.CloseWindowStation(s.Winsta);
                    s.Winsta = IntPtr.Zero;
                    return null;
                }
                s.NewlyOwned = true;
                s.Desktop = s.WinstaName + "\\" + s.DeskName;
                if (!Native.SetProcessWindowStation(s.Winsta))
                {
                    error = "SetProcessWindowStation(new) win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "winsta_switch";
                    s.Dispose();
                    return null;
                }
                switched = true;
                s.Desk = Native.CreateDesktop(s.DeskName, IntPtr.Zero, IntPtr.Zero, 0, Native.DESKTOP_ALL, psa);
                if (s.Desk == IntPtr.Zero)
                {
                    error = "CreateDesktop win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "desktop_create";
                    Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                    switched = false;
                    s.Dispose();
                    return null;
                }
                return s;
            }
            finally
            {
                if (switched)
                {
                    if (prevSta != IntPtr.Zero) Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                }
                if (psa != IntPtr.Zero) Marshal.FreeHGlobal(psa);
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
            }
        }

        public static SyntheticStation TryCreateNamedOwned(string winstaName, string deskName, string userSid, string packageSid, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(winstaName) || Native.IsWinSta0Name(winstaName) ||
                !IsOwnedStationName(winstaName) || !IsOwnedDeskName(deskName))
            {
                error = "invalid_station_or_desktop_name";
                return null;
            }
            if (!SidTextOk(userSid) || !SidTextOk(packageSid))
            {
                error = "invalid_sid_text";
                return null;
            }
            IntPtr prevSta = Native.GetProcessWindowStation();
            IntPtr prevDesk = Native.GetThreadDesktop(Native.GetCurrentThreadId());
            string prevName = Native.GetUserObjectName(prevSta);
            if (Native.IsWinSta0Name(winstaName) || string.Equals(winstaName, prevName, StringComparison.OrdinalIgnoreCase))
            {
                error = "refused_existing_or_winsta0";
                return null;
            }
            string staSddl = "D:P(A;;GA;;;SY)(A;;0x" + Native.WINSTA_MIN_START.ToString("x") + ";;;" + userSid +
                ")(A;;0x" + Native.WINSTA_MIN_START.ToString("x") + ";;;" + packageSid + ")S:(ML;;NW;;;LW)";
            string deskSddl = "D:P(A;;GA;;;SY)(A;;0x" + Native.DESKTOP_MIN_START.ToString("x") + ";;;" + userSid +
                ")(A;;0x" + Native.DESKTOP_MIN_START.ToString("x") + ";;;" + packageSid + ")S:(ML;;NW;;;LW)";
            IntPtr staSd = IntPtr.Zero;
            IntPtr deskSd = IntPtr.Zero;
            IntPtr psaSta = IntPtr.Zero;
            IntPtr psaDesk = IntPtr.Zero;
            SyntheticStation s = new SyntheticStation();
            s.WinstaName = winstaName;
            s.DeskName = deskName;
            bool switched = false;
            try
            {
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(staSddl, Native.SDDL_REVISION_1, out staSd, IntPtr.Zero) ||
                    staSd == IntPtr.Zero)
                {
                    error = "station_sddl win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "winsta_sd";
                    s.Dispose();
                    return null;
                }
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(deskSddl, Native.SDDL_REVISION_1, out deskSd, IntPtr.Zero) ||
                    deskSd == IntPtr.Zero)
                {
                    error = "desktop_sddl win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "desktop_sd";
                    s.Dispose();
                    return null;
                }
                Native.SECURITY_ATTRIBUTES saSta = new Native.SECURITY_ATTRIBUTES();
                saSta.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                saSta.lpSecurityDescriptor = staSd;
                saSta.bInheritHandle = 0;
                psaSta = Marshal.AllocHGlobal(saSta.nLength);
                Marshal.StructureToPtr(saSta, psaSta, false);
                Native.SECURITY_ATTRIBUTES saDesk = new Native.SECURITY_ATTRIBUTES();
                saDesk.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                saDesk.lpSecurityDescriptor = deskSd;
                saDesk.bInheritHandle = 0;
                psaDesk = Marshal.AllocHGlobal(saDesk.nLength);
                Marshal.StructureToPtr(saDesk, psaDesk, false);

                s.Winsta = Native.CreateWindowStation(winstaName, Native.CWF_CREATE_ONLY,
                    Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL | Native.WRITE_DAC, psaSta);
                int lastErr = Marshal.GetLastWin32Error();
                if (s.Winsta == IntPtr.Zero)
                {
                    error = "CreateWindowStation(named,CWF_CREATE_ONLY) win32=" + lastErr + " name=" + winstaName;
                    s.ErrorCode = lastErr == Native.ERROR_ALREADY_EXISTS ? "station_exists" : "winsta_create";
                    s.Dispose();
                    return null;
                }
                if (lastErr == Native.ERROR_ALREADY_EXISTS)
                {
                    error = "CreateWindowStation already exists; refused";
                    s.ErrorCode = "station_exists";
                    s.Dispose();
                    return null;
                }
                string gotName = Native.GetUserObjectName(s.Winsta);
                if (string.IsNullOrEmpty(gotName) || Native.IsWinSta0Name(gotName) ||
                    !string.Equals(gotName, winstaName, StringComparison.Ordinal) ||
                    string.Equals(gotName, prevName, StringComparison.OrdinalIgnoreCase))
                {
                    error = "named CreateWindowStation returned unexpected station '" + gotName + "'; refused";
                    s.ErrorCode = "winsta_mismatch";
                    s.Dispose();
                    return null;
                }
                s.NewlyOwned = true;
                s.Desktop = winstaName + "\\" + deskName;
                if (!Native.SetProcessWindowStation(s.Winsta))
                {
                    error = "SetProcessWindowStation(new) win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "winsta_switch";
                    s.Dispose();
                    return null;
                }
                switched = true;
                s.Desk = Native.CreateDesktop(deskName, IntPtr.Zero, IntPtr.Zero, 0,
                    Native.DESKTOP_ALL | Native.READ_CONTROL | Native.WRITE_DAC, psaDesk);
                if (s.Desk == IntPtr.Zero)
                {
                    error = "CreateDesktop win32=" + Marshal.GetLastWin32Error();
                    s.ErrorCode = "desktop_create";
                    Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                    switched = false;
                    s.Dispose();
                    return null;
                }
                string gotDesk = Native.GetUserObjectName(s.Desk);
                if (!string.Equals(gotDesk, deskName, StringComparison.Ordinal))
                {
                    error = "CreateDesktop name mismatch '" + gotDesk + "'";
                    s.ErrorCode = "desktop_mismatch";
                    Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                    switched = false;
                    s.Dispose();
                    return null;
                }
                string staRead;
                string deskRead;
                string sdErr;
                if (!Native.TryReadUserObjectSddl(s.Winsta, out staRead, out sdErr) ||
                    !Native.TryReadUserObjectSddl(s.Desk, out deskRead, out sdErr))
                {
                    error = "sddl_readback " + sdErr;
                    s.ErrorCode = "winsta_sddl";
                    Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                    switched = false;
                    s.Dispose();
                    return null;
                }
                s.GrantedPackageSid = packageSid;
                if (PackageAceTooWide(staRead, packageSid) || PackageAceTooWide(deskRead, packageSid))
                {
                    error = "package ACE too wide in readback SDDL";
                    s.ErrorCode = "winsta_acl";
                    Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                    switched = false;
                    s.Dispose();
                    return null;
                }
                Native.SetProcessWindowStation(prevSta);
                if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                switched = false;
                return s;
            }
            finally
            {
                if (switched)
                {
                    if (prevSta != IntPtr.Zero) Native.SetProcessWindowStation(prevSta);
                    if (prevDesk != IntPtr.Zero) Native.SetThreadDesktop(prevDesk);
                }
                if (psaSta != IntPtr.Zero) Marshal.FreeHGlobal(psaSta);
                if (psaDesk != IntPtr.Zero) Marshal.FreeHGlobal(psaDesk);
                if (staSd != IntPtr.Zero) Native.LocalFree(staSd);
                if (deskSd != IntPtr.Zero) Native.LocalFree(deskSd);
            }
        }

        static bool IsOwnedStationName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 10 || name.Length > 32)
            {
                return false;
            }
            if (!name.StartsWith("nmzpsta", StringComparison.Ordinal))
            {
                return false;
            }
            return HexTail(name, 7);
        }

        static bool IsOwnedDeskName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 11 || name.Length > 32)
            {
                return false;
            }
            if (!name.StartsWith("nmzpdesk", StringComparison.Ordinal))
            {
                return false;
            }
            return HexTail(name, 8);
        }

        static bool HexTail(string name, int prefixLen)
        {
            for (int i = prefixLen; i < name.Length; i++)
            {
                char c = name[i];
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!hex)
                {
                    return false;
                }
            }
            return name.Length > prefixLen;
        }

        static bool SidTextOk(string sid)
        {
            if (string.IsNullOrEmpty(sid) || sid.Length < 5 || sid.Length > 256)
            {
                return false;
            }
            if (!sid.StartsWith("S-1-", StringComparison.Ordinal))
            {
                return false;
            }
            for (int i = 0; i < sid.Length; i++)
            {
                char c = sid[i];
                if (!((c >= '0' && c <= '9') || c == 'S' || c == '-'))
                {
                    return false;
                }
            }
            return true;
        }

        static bool PackageAceTooWide(string sddl, string packageSid)
        {
            if (string.IsNullOrEmpty(sddl) || string.IsNullOrEmpty(packageSid))
            {
                return true;
            }
            if (sddl.IndexOf("(A;;GA;;;" + packageSid + ")", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            if (sddl.IndexOf("0x37f", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            return false;
        }

        static bool TryUserOnlySd(out IntPtr sd, out string error)
        {
            sd = IntPtr.Zero;
            error = "";
            string user = null;
            try
            {
                System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (id != null && id.User != null)
                {
                    user = id.User.Value;
                }
            }
            catch (Exception ex)
            {
                error = TextUtil.Sanitize(ex.Message);
                return false;
            }
            if (string.IsNullOrEmpty(user))
            {
                error = "no current user sid";
                return false;
            }
            string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;" + user + ")";
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, Native.SDDL_REVISION_1, out sd, IntPtr.Zero) || sd == IntPtr.Zero)
            {
                error = "ConvertStringSecurityDescriptor win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            return true;
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (Desk != IntPtr.Zero)
            {
                Native.CloseDesktop(Desk);
                Desk = IntPtr.Zero;
            }
            if (Winsta != IntPtr.Zero)
            {
                Native.CloseWindowStation(Winsta);
                Winsta = IntPtr.Zero;
            }
        }
    }

    internal static class Supervisor
    {
        public static int RunConfigFile(string path, string resultPath)
        {
            if (TokenBridge.CurrentLooksElevated())
            {
                LaunchResult elev = LaunchResult.Fail("elevated_supervisor_refused",
                    "production --config refuses elevated I/O; use --privileged-init --execute-payload with limited impersonation",
                    Native.ERROR_ACCESS_DENIED);
                Console.Write(Json.Stringify(elev.ToJson()));
                return 3;
            }
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                LaunchResult miss = LaunchResult.Fail("config_missing", "config file not found", 2);
                WriteResult(resultPath, miss);
                Console.Write(Json.Stringify(miss.ToJson()));
                return 2;
            }
            FileInfo fi = new FileInfo(path);
            if (fi.Length > Constants.JsonMaxBytes)
            {
                LaunchResult big = LaunchResult.Fail("config_invalid", "json too large", 2);
                WriteResult(resultPath, big);
                Console.Write(Json.Stringify(big.ToJson()));
                return 2;
            }
            string json = File.ReadAllText(path, Encoding.UTF8);
            LaunchRequest req;
            try
            {
                req = Config.FromJson(json);
            }
            catch (Exception ex)
            {
                LaunchResult bad = LaunchResult.Fail("config_invalid", TextUtil.Sanitize(ex.Message), 2);
                WriteResult(resultPath, bad);
                Console.Write(Json.Stringify(bad.ToJson()));
                return 2;
            }
            req.Level = SandboxLevel.Production;
            LaunchResult r = Launch(req, null);
            WriteResult(resultPath, r);
            Console.Write(Json.Stringify(r.ToJson()));
            if (!r.Ok)
            {
                return string.Equals(r.ErrorCode, "brokered_filter_not_installed", StringComparison.Ordinal) ? 3 : 1;
            }
            return r.ExitCode == 0 ? 0 : 1;
        }

        static void WriteResult(string path, LaunchResult r)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            if (TokenBridge.CurrentLooksElevated())
            {
                return;
            }
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.WriteAllText(path, Json.Stringify(r.ToJson()), new UTF8Encoding(false));
            }
            catch
            {
            }
        }

        public static LaunchResult Launch(LaunchRequest req, Log log)
        {
            ChildSession session;
            LaunchResult r = Start(req, log, out session);
            if (session == null)
            {
                return r;
            }
            try
            {
                if (req.WaitForExit)
                {
                    Wait(session, req.DeadlineMs, r);
                    if (req.Grok != null && r.Ok) GrokWorkspace.Capture(req, session, r);
                }
                else
                {
                    r.Ok = string.IsNullOrEmpty(r.ErrorCode);
                    r.ExitCode = -1;
                }
                return r;
            }
            finally
            {
                if (req.WaitForExit)
                {
                    session.Dispose();
                }
            }
        }

        public static LaunchResult Start(LaunchRequest req, Log log, out ChildSession session)
        {
            session = null;
            Clock clock = new Clock();
            if (req == null)
            {
                return LaunchResult.Fail("null_request", "request is null", 0);
            }
            if (req.Grok != null && (!req.PrivilegedSession || req.Channel == null))
                return LaunchResult.Fail("grok_privileged_channel_required", "use the owned controller protocol", 0);
            if (req.Level == SandboxLevel.Production)
            {
                if (!string.Equals(req.NetworkMode, "offline", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(req.NetworkMode, "brokered", StringComparison.OrdinalIgnoreCase))
                {
                    return LaunchResult.Fail("invalid_network_mode", "network_mode must be offline or brokered", 0);
                }
                if (string.Equals(req.NetworkMode, "brokered", StringComparison.OrdinalIgnoreCase))
                {
                    if (req.GatewayPort < 1 || req.GatewayPort > 65535 || req.ControllerPid <= 0 || req.ControllerCreationTime <= 0)
                    {
                        LaunchResult br = LaunchResult.Fail("brokered_controller_missing",
                            "brokered mode requires gateway_port, controller_pid, controller_creation_time", 0);
                        br.ElapsedMs = clock.Elapsed;
                        return br;
                    }
                }
                req.Desktop = "";
                req.UseUiLimits = true;
                req.UiLimitFlags = req.UiLimitFlags | Constants.RequiredUiFlags;
                if (req.SkipPrivateDesktopForBrokeredTest)
                {
                    req.UsePrivateDesktop = false;
                    req.RequirePrivateDesktop = false;
                }
                else
                {
                    req.UsePrivateDesktop = true;
                    req.RequirePrivateDesktop = true;
                }
                req.UseStdPipes = true;
                req.UseRegistryReadCapability = true;
                if (req.PayloadToken == IntPtr.Zero && TokenBridge.CurrentLooksElevated())
                {
                    return LaunchResult.Fail("elevated_without_limited_payload",
                        "refusing production launch as elevated token without verified limited payload",
                        Native.ERROR_ACCESS_DENIED);
                }
            }
            if (string.IsNullOrEmpty(req.Executable) || !File.Exists(req.Executable))
            {
                return LaunchResult.Fail("executable_missing", "executable not found", 2);
            }

            bool brokered = req.Level == SandboxLevel.Production &&
                string.Equals(req.NetworkMode, "brokered", StringComparison.OrdinalIgnoreCase);
            ControllerLifetime ctrl = null;
            if (brokered)
            {
                string cErr;
                if (!ControllerLifetime.TryOpen(req.ControllerPid, req.ControllerCreationTime, 0, out ctrl, out cErr))
                {
                    return LaunchResult.Fail("brokered_controller", cErr, Native.ERROR_ACCESS_DENIED);
                }
            }

            bool needAc = req.Level == SandboxLevel.Production ||
                req.Level == SandboxLevel.InternalLpac ||
                req.Level == SandboxLevel.InternalAppContainer;
            bool needJob = req.Level != SandboxLevel.Unconstrained;
            bool lpac = req.Level == SandboxLevel.Production || req.Level == SandboxLevel.InternalLpac;

            ChildSession sess = new ChildSession();
            sess.DeleteProfile = req.DeleteProfileAfter;
            sess.Controller = ctrl;
            ctrl = null;
            sess.FilterWorld = req.FilterWorld;
            LaunchResult result = new LaunchResult();
            result.DegradedToNormalProcess = false;
            result.AppContainerKind = lpac ? "lpac" : (needAc ? "appcontainer" : "none");
            result.LpacOptOut = lpac;
            result.DisplaySettingsIsNotAntiScreenshot = true;
            result.HandleWhitelistExplicit = true;
            result.JobHandleNotInherited = true;
            sess.Result = result;

            try
            {
                if (needAc)
                {
                    string acErr = "";
                    int acWin = 0;
                    if (brokered)
                    {
                        Nmzp.NativeEgressFilter.OwnedNetworkJobLease lease;
                        string lerr;
                        lease = req.ExistingLease;
                        lerr = "";
                        if (lease == null && !Nmzp.NativeEgressFilter.OwnedNetworkJobLease.TryCreate(out lease, out lerr))
                        {
                            return AbortStart(sess, result, "lease_create", lerr ?? "TryCreate failed", 0);
                        }
                        sess.Lease = lease;
                        req.ExistingLease = null;
                        if (req.ExistingAc != null) {
                            if (!string.Equals(req.ExistingAc.SidText, lease.PackageSid, StringComparison.Ordinal))
                                return AbortStart(sess, result, "lease_profile_mismatch", "existing profile differs from owned lease", 0);
                            sess.Ac = req.ExistingAc;
                            req.ExistingAc = null;
                        } else sess.Ac = AppContainerSession.BorrowFromLease(lease, out acErr);
                        if (sess.Ac == null)
                        {
                            return AbortStart(sess, result, "lease_borrow_profile", acErr, 0);
                        }
                        sess.Job = lease.DangerousGetJobHandle();
                        sess.JobBorrowed = true;
                        sess.JobName = lease.JobName;
                        result.Extra.Map["job_name"] = JVal.Str(lease.JobName);
                        result.Extra.Map["lease_profile"] = JVal.Str(lease.ProfileName);
                    }
                    else if (req.ExistingAc != null)
                    {
                        sess.Ac = req.ExistingAc;
                        req.ExistingAc = null;
                    }
                    else
                    {
                        sess.Ac = AppContainerSession.CreateUnique(out acErr, out acWin);
                    }
                    if (sess.Ac == null)
                    {
                        return LaunchResult.Fail("appcontainer_profile", acErr, acWin);
                    }
                    result.ProfileName = sess.Ac.Name;
                    result.AppContainerSid = sess.Ac.SidText ?? "";
                    result.ProfileFolder = sess.Ac.Folder ?? "";
                    sess.ProfileFolder = result.ProfileFolder;
                    if (string.IsNullOrEmpty(sess.Ac.Folder))
                    {
                        return AbortStart(sess, result, "appcontainer_folder", "GetAppContainerFolderPath empty", 0);
                    }
                    string dirErr;
                    if (!SessionFiles.TryCreateDirectory(req.ImpersonationToken, sess.Ac.Folder, out dirErr) ||
                        !SessionFiles.TryCreateDirectory(req.ImpersonationToken, Path.Combine(sess.Ac.Folder, "app"), out dirErr) ||
                        !SessionFiles.TryCreateDirectory(req.ImpersonationToken, Path.Combine(sess.Ac.Folder, "workspace"), out dirErr))
                    {
                        return AbortStart(sess, result, "staging_dir", dirErr, 0);
                    }
                    result.StagingApp = Path.Combine(sess.Ac.Folder, "app");
                    result.StagingWorkspace = Path.Combine(sess.Ac.Folder, "workspace");
                    sess.StagingApp = result.StagingApp;
                    sess.StagingWorkspace = result.StagingWorkspace;
                }

                string launchExe = req.Executable;
                string cwd = req.WorkingDirectory;
                if (needAc && req.CopyExeToProfile)
                {
                    string dest = Path.Combine(result.StagingApp, Path.GetFileName(req.Executable));
                    string copyErr;
                    if (!SessionFiles.TryCopyFile(req.ImpersonationToken, req.Executable, dest, out copyErr))
                    {
                        return AbortStart(sess, result, "exe_copy", copyErr, 0);
                    }
                    launchExe = dest;
                    if (string.IsNullOrEmpty(cwd))
                    {
                        cwd = result.StagingApp;
                    }
                }
                if (string.IsNullOrEmpty(cwd))
                {
                    cwd = Path.GetDirectoryName(launchExe);
                }

                if (needJob)
                {
                    int jobWin;
                    string jobName = null;
                    if (sess.JobBorrowed)
                    {
                        result.KillOnCloseSet = true;
                    }
                    else
                    {
                    if (needAc && !string.IsNullOrEmpty(result.ProfileName))
                    {
                        jobName = "Local\\" + result.ProfileName + ".job";
                        sess.JobName = jobName;
                        result.Extra.Map["job_name"] = JVal.Str(jobName);
                    }
                    string jobSddl = null;
                    if (req.ExclusiveJobDacl)
                    {
                        jobSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
                    }
                    sess.Job = JobObject.CreateNonInheritable(jobName, jobSddl, out jobWin);
                    if (sess.Job == IntPtr.Zero)
                    {
                        return AbortStart(sess, result, "job_create", "CreateJobObject win32=" + jobWin + " name=" + jobName, jobWin);
                    }
                    string kd;
                    if (!JobObject.SetKillOnClose(sess.Job, out kd))
                    {
                        return AbortStart(sess, result, "job_kill_on_close", kd, 0);
                    }
                    result.KillOnCloseSet = true;
                    }
                    bool ui = req.UseUiLimits || req.Level == SandboxLevel.Production;
                    uint uiFlags = req.Level == SandboxLevel.Production ? (req.UiLimitFlags | Constants.RequiredUiFlags) : req.UiLimitFlags;
                    if (ui && !sess.JobBorrowed)
                    {
                        uint actual;
                        string ud;
                        if (!JobObject.SetUiLimits(sess.Job, uiFlags, out actual, out ud))
                        {
                            return AbortStart(sess, result, "job_ui_limits", ud, 0);
                        }
                        result.UiLimitsSet = true;
                        result.UiLimitsFlags = actual;
                        result.UiLimitNames = JobObject.FlagNames(actual);
                    }
                    else if (sess.JobBorrowed)
                    {
                        result.UiLimitsSet = true;
                    }
                }

                string desktop = req.Desktop;
                if (req.Level == SandboxLevel.Production && req.RequirePrivateDesktop)
                {
                    desktop = "";
                    if (req.OwnedStation != null)
                    {
                        sess.Station = req.OwnedStation;
                        req.OwnedStation = null;
                        if (brokered && (sess.Ac == null || !string.Equals(sess.Station.GrantedPackageSid, sess.Ac.SidText, StringComparison.Ordinal)))
                            return AbortStart(sess, result, "station_profile_mismatch", "private station must belong to the held lease profile", 0);
                        desktop = sess.Station.Desktop;
                        result.Extra.Map["station_source"] = JVal.Str("privileged_named");
                        string staSddl;
                        string deskSddl;
                        string sdErr;
                        if (!Native.TryReadUserObjectSddl(sess.Station.Winsta, out staSddl, out sdErr) ||
                            !Native.TryReadUserObjectSddl(sess.Station.Desk, out deskSddl, out sdErr))
                        {
                            return AbortStart(sess, result, "winsta_sddl", "readback failed " + sdErr, 0);
                        }
                        result.Extra.Map["winsta_sddl"] = JVal.Str(staSddl);
                        result.Extra.Map["desk_sddl"] = JVal.Str(deskSddl);
                    }
                    else
                    {
                        string staErr;
                        sess.Station = SyntheticStation.TryCreateUnnamedOwned(out staErr);
                        if (sess.Station == null)
                        {
                            return AbortStart(sess, result, "requires_admin",
                                "private window station not available without admin-named CreateWindowStation; " + staErr, 5);
                        }
                        desktop = sess.Station.Desktop;
                        if (sess.Ac != null && sess.Ac.Sid != IntPtr.Zero)
                        {
                            uint gw = Native.GrantSidOnHandle(sess.Station.Winsta, Native.SE_WINDOW_OBJECT, sess.Ac.Sid,
                                Native.WINSTA_MIN_START);
                            uint gd = Native.GrantSidOnHandle(sess.Station.Desk, Native.SE_WINDOW_OBJECT, sess.Ac.Sid,
                                Native.DESKTOP_MIN_START);
                            result.Extra.Map["grant_winsta"] = JVal.Num(gw);
                            result.Extra.Map["grant_desk"] = JVal.Num(gd);
                            if (gw != 0 || gd != 0)
                            {
                                return AbortStart(sess, result, "winsta_grant",
                                    "GrantSidOnHandle failed winsta=" + gw + " desk=" + gd + "; not launching", 0);
                            }
                            string staSddl;
                            string deskSddl;
                            string sdErr;
                            if (!Native.TryReadUserObjectSddl(sess.Station.Winsta, out staSddl, out sdErr) ||
                                !Native.TryReadUserObjectSddl(sess.Station.Desk, out deskSddl, out sdErr))
                            {
                                return AbortStart(sess, result, "winsta_sddl", "readback failed " + sdErr, 0);
                            }
                            result.Extra.Map["winsta_sddl"] = JVal.Str(staSddl);
                            result.Extra.Map["desk_sddl"] = JVal.Str(deskSddl);
                        }
                    }
                }
                if (!string.IsNullOrEmpty(desktop))
                {
                    int slash = desktop.IndexOf('\\');
                    if (slash > 0)
                    {
                        result.WindowStation = desktop.Substring(0, slash);
                        result.Desktop = desktop;
                    }
                    else
                    {
                        result.Desktop = desktop;
                    }
                }

                string envDetail;
                sess.Env = EnvBlock.Build(req, result.StagingApp, string.IsNullOrEmpty(result.ProfileFolder) ? cwd : result.ProfileFolder, out envDetail);
                result.EnvironmentMode = "fixed_allowlist_reserved_last " + envDetail;

                if (lpac && req.UseRegistryReadCapability)
                {
                    sess.Caps = CapabilitySet.TryRegistryRead();
                    result.Extra.Map["registryRead"] = JVal.Bool(sess.Caps != null);
                }

                IntPtr[] inherit = new IntPtr[0];
                IntPtr hIn = IntPtr.Zero;
                IntPtr hOut = IntPtr.Zero;
                IntPtr hErr = IntPtr.Zero;
                if (req.UseStdPipes)
                {
                    string pipeErr;
                    if (!StdPipes.Create(sess, out pipeErr))
                    {
                        return AbortStart(sess, result, "stdio_pipes", pipeErr, 0);
                    }
                    inherit = new IntPtr[] { sess.ChildStdin, sess.ChildStdout, sess.ChildStderr };
                    hIn = sess.ChildStdin;
                    hOut = sess.ChildStdout;
                    hErr = sess.ChildStderr;
                }

                string cmd = TextUtil.BuildCommandLine(launchExe, req.Arguments);
                int createErr;
                bool created = ProcessCreator.CreateSuspended(
                    launchExe,
                    cmd,
                    cwd,
                    desktop,
                    needAc ? sess.Ac.Sid : IntPtr.Zero,
                    lpac,
                    sess.Env,
                    inherit,
                    sess.Caps != null ? sess.Caps.Array : IntPtr.Zero,
                    sess.Caps != null ? sess.Caps.Count : 0,
                    hIn,
                    hOut,
                    hErr,
                    req.PayloadToken,
                    out sess.Process,
                    out sess.Thread,
                    out createErr);
                if (!created)
                {
                    string createApi = req.PayloadToken != IntPtr.Zero ? "CreateProcessAsUserW" : "CreateProcess";
                    return AbortStart(sess, result, "create_process",
                        createApi + " win32=" + createErr + " lpac=" + lpac + " desktop=" + (desktop ?? ""),
                        createErr);
                }
                sess.CloseChildPipeEnds();

                if (needJob)
                {
                    if (req.InjectJobAssignFailure)
                    {
                        if (sess.Job != IntPtr.Zero && !sess.JobBorrowed)
                        {
                            Native.CloseHandle(sess.Job);
                            sess.Job = IntPtr.Zero;
                        }
                        bool assignedBad = Native.AssignProcessToJobObject(IntPtr.Zero, sess.Process);
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "job_assign",
                            "injected AssignProcessToJobObject failure assigned=" + assignedBad + "; suspended process terminated; not degraded",
                            assignedBad ? 0 : Marshal.GetLastWin32Error());
                    }
                    if (!req.InjectSkipJobAssign)
                    {
                        if (!Native.AssignProcessToJobObject(sess.Job, sess.Process))
                        {
                            int assignErr = Marshal.GetLastWin32Error();
                            Native.TerminateProcess(sess.Process, 99);
                            return AbortStart(sess, result, "job_assign",
                                "AssignProcessToJobObject win32=" + assignErr + "; suspended process terminated; not degraded",
                                assignErr);
                        }
                    }
                    bool inJob;
                    Native.IsProcessInJob(sess.Process, sess.Job, out inJob);
                    result.InJob = inJob;
                    if (!inJob && !req.InjectSkipJobAssign)
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "job_membership",
                            "IsProcessInJob false after assign; terminated", 0);
                    }
                }

                if (sess.Lease != null)
                {
                    string bindErr;
                    int tok46 = QueryLpacTokenClass(sess.Process);
                    result.Extra.Map["token_lpac_class46"] = JVal.Num(tok46);
                    if (!sess.Lease.BindSuspendedProcess(sess.Process, out bindErr))
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "lease_bind", bindErr ?? "BindSuspendedProcess failed", 0);
                    }
                    result.Extra.Map["lease_bound"] = JVal.Bool(true);
                    if (req.AfterBindHook != null)
                    {
                        req.AfterBindHook();
                    }
                    if (sess.Controller != null && !sess.Controller.IsAlive())
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "controller_exited", "controller exited before resume", 0);
                    }
                    string prepErr;
                    if (!LeaseNetwork.PrepareGuarded(sess.Lease, req.GatewayPort, sess.FilterWorld, req, out prepErr))
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "lease_prepare", prepErr ?? "PrepareNetwork failed", 0);
                    }
                    result.Extra.Map["lease_network_ready"] = JVal.Bool(true);
                    if (sess.Controller != null && !sess.Controller.IsAlive())
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "controller_exited", "controller exited after prepare", 0);
                    }
                    int payloadPid = Native.GetProcessId(sess.Process);
                    if (sess.Controller != null && payloadPid == sess.Controller.Pid)
                    {
                        Native.TerminateProcess(sess.Process, 99);
                        return AbortStart(sess, result, "controller_is_payload", "controller pid matches payload", 0);
                    }
                }

                uint resumed;
                string resumeError;
                if (!ResumeBarrier.TryResume(delegate {
                    bool member;
                    if (needJob && (sess.Job == IntPtr.Zero || !Native.IsProcessInJob(sess.Process, sess.Job, out member) || !member)) return false;
                    return !brokered || (sess.Lease != null && sess.Lease.State == Nmzp.NativeEgressFilter.OwnedSessionState.NetworkReady);
                }, delegate { return !brokered || (sess.Controller != null && sess.Controller.IsAlive()); },
                   delegate { return Native.ResumeThread(sess.Thread); }, out resumed, out resumeError))
                {
                    return AbortStart(sess, result, "resume_guard", resumeError, 0);
                }
                sess.Pid = Native.GetProcessId(sess.Process);
                result.Pid = sess.Pid;
                result.ElapsedMs = clock.Elapsed;
                sess.Channel = req.Channel;
                if (sess.Channel != null) sess.Channel.Attach(sess);
                session = sess;
                if (log != null)
                {
                    log.Info("started pid=" + sess.Pid + " kind=" + result.AppContainerKind + " job=" + result.InJob);
                }
                return result;
            }
            catch (Exception ex)
            {
                LaunchResult f = AbortStart(sess, result, "exception", TextUtil.Sanitize(ex.GetType().Name + " " + ex.Message), 0);
                f.ElapsedMs = clock.Elapsed;
                return f;
            }
        }

        public static void Wait(ChildSession session, int deadlineMs, LaunchResult result)
        {
            if (session == null || session.Process == IntPtr.Zero)
            {
                result.Ok = false;
                result.ErrorCode = "no_process";
                result.Error = "wait without process";
                result.DegradedToNormalProcess = false;
                return;
            }
            Clock clock = new Clock();
            uint remain = (uint)Math.Max(500, deadlineMs);
            while (true)
            {
                session.DrainPipes();
                if (session.Controller != null && !session.Controller.IsAlive())
                {
                    session.KillTree();
                    result.Ok = false;
                    result.ErrorCode = "controller_exited";
                    result.Error = "controller process exited; job terminated";
                    result.DegradedToNormalProcess = false;
                    session.CopyIo(result);
                    return;
                }
                uint slice = remain > 50 ? 50 : remain;
                uint wait = Native.WaitForSingleObject(session.Process, slice);
                if (wait == Native.WAIT_FAILED)
                {
                    session.KillTree();
                    result.Ok = false;
                    result.ErrorCode = "wait_failed";
                    result.Error = "WaitForSingleObject failed win32=" + Marshal.GetLastWin32Error();
                    result.DegradedToNormalProcess = false;
                    session.CopyIo(result);
                    return;
                }
                if (wait == Native.WAIT_OBJECT_0)
                {
                    session.DrainConcurrent(Math.Max(50, deadlineMs - clock.Elapsed), true);
                    break;
                }
                int used = clock.Elapsed;
                if (used >= deadlineMs)
                {
                    session.CancelAndWait(2000);
                    uint codeT;
                    if (!Native.GetExitCodeProcess(session.Process, out codeT))
                    {
                        result.Ok = false;
                        result.ErrorCode = "exit_code";
                        result.Error = "GetExitCodeProcess failed after deadline";
                        session.CopyIo(result);
                        return;
                    }
                    result.Ok = false;
                    result.ErrorCode = "deadline";
                    result.Error = "process exceeded deadline_ms=" + deadlineMs;
                    result.ExitCode = unchecked((int)codeT);
                    session.CopyIo(result);
                    return;
                }
                remain = (uint)Math.Max(1, deadlineMs - used);
            }
            if (!session.WaitJobIdle(Math.Max(500, Math.Min(deadlineMs, 15000))))
            {
                session.DeleteProfile = false;
                result.Extra.Map["job_tree_idle"] = JVal.Bool(false);
            }
            uint code;
            if (!Native.GetExitCodeProcess(session.Process, out code))
            {
                result.Ok = false;
                result.ErrorCode = "exit_code";
                result.Error = "GetExitCodeProcess failed";
                result.DegradedToNormalProcess = false;
                session.CopyIo(result);
                return;
            }
            result.ExitCode = unchecked((int)code);
            if (string.IsNullOrEmpty(result.ErrorCode))
            {
                result.Ok = true;
                result.Error = "";
            }
            session.CopyIo(result);
        }

        static int QueryLpacTokenClass(IntPtr process)
        {
            IntPtr tok;
            if (!Native.OpenProcessToken(process, Native.TOKEN_QUERY, out tok))
            {
                return -Marshal.GetLastWin32Error();
            }
            try
            {
                IntPtr mem = Marshal.AllocHGlobal(4);
                try
                {
                    uint ret;
                    if (!Native.GetTokenInformation(tok, 46, mem, 4, out ret))
                    {
                        return -Marshal.GetLastWin32Error();
                    }
                    return Marshal.ReadInt32(mem);
                }
                finally
                {
                    Marshal.FreeHGlobal(mem);
                }
            }
            finally
            {
                Native.CloseHandle(tok);
            }
        }

        static LaunchResult AbortStart(ChildSession sess, LaunchResult result, string code, string error, int win32)
        {
            if (sess != null && sess.Process != IntPtr.Zero)
            {
                Native.TerminateProcess(sess.Process, 99);
            }
            result.Ok = false;
            result.ErrorCode = code;
            result.Error = error;
            result.Win32 = win32;
            result.DegradedToNormalProcess = false;
            result.ExitCode = 1;
            if (sess != null)
            {
                sess.Dispose();
            }
            return result;
        }
    }

    internal sealed class ChildSession : IDisposable
    {
        public IntPtr Process;
        public IntPtr Thread;
        public IntPtr Job;
        public bool JobBorrowed;
        public Nmzp.NativeEgressFilter.OwnedNetworkJobLease Lease;
        public Nmzp.NativeEgressFilter.IFilterWorld FilterWorld;
        public ControllerLifetime Controller;
        public IntPtr Env;
        public AppContainerSession Ac;
        public SyntheticStation Station;
        public CapabilitySet Caps;
        public int Pid;
        public string ProfileFolder;
        public string StagingApp;
        public string StagingWorkspace;
        public string JobName;
        public bool DeleteProfile = true;
        public LaunchResult Result;
        public IntPtr ChildStdin;
        public IntPtr ChildStdout;
        public IntPtr ChildStderr;
        public ControllerChannel Channel;
        public IntPtr StdinWrite;
        public IntPtr StdoutRead;
        public IntPtr StderrRead;
        public OutputSanitizer OutSan = new OutputSanitizer();
        public OutputSanitizer ErrSan = new OutputSanitizer();
        public Decoder OutDec = Encoding.UTF8.GetDecoder();
        public Decoder ErrDec = Encoding.UTF8.GetDecoder();
        public StringBuilder OutBuf = new StringBuilder();
        public StringBuilder ErrBuf = new StringBuilder();
        public bool OutTruncated;
        public bool ErrTruncated;
        bool disposed;

        public void KillTree()
        {
            if (Job != IntPtr.Zero)
            {
                Native.TerminateJobObject(Job, 1);
            }
            if (Process != IntPtr.Zero)
            {
                Native.TerminateProcess(Process, 1);
            }
        }

        public bool DrainIncomplete;

        bool CheckController()
        {
            if (!disposed && Channel != null && Channel.Failed) { KillTree(); if (Result != null) { Result.Ok=false; Result.ErrorCode="controller_channel_lost"; } return false; }
            if (disposed || Controller == null || Controller.IsAlive()) return true;
            KillTree();
            if (Result != null) {
                Result.Ok = false;
                Result.ErrorCode = "controller_exited";
                Result.Error = "controller exited during tree/pipe wait; termination requested";
            }
            return false;
        }

        public void CancelAndWait(int waitMs)
        {
            KillTree();
            if (Process != IntPtr.Zero)
            {
                Native.WaitForSingleObject(Process, (uint)Math.Max(1, Math.Min(waitMs, 2000)));
            }
            WaitJobIdle(waitMs);
        }

        public bool WaitJobIdle(int waitMs)
        {
            Clock c = new Clock();
            if (Job == IntPtr.Zero)
            {
                DrainConcurrent(Math.Max(1, waitMs), true);
                return !DrainIncomplete;
            }
            while (c.Elapsed < waitMs)
            {
                if (!CheckController()) return false;
                DrainConcurrent(15, false);
                uint active;
                if (!JobObject.TryGetActiveProcesses(Job, out active))
                {
                    DrainConcurrent(Math.Max(1, waitMs - c.Elapsed), true);
                    DeleteProfile = false;
                    return false;
                }
                if (active == 0)
                {
                    DrainConcurrent(Math.Max(1, waitMs - c.Elapsed), true);
                    return !DrainIncomplete;
                }
                System.Threading.Thread.Sleep(15);
            }
            DrainConcurrent(50, false);
            uint left = uint.MaxValue;
            JobObject.TryGetActiveProcesses(Job, out left);
            if (left == 0)
            {
                DrainConcurrent(100, true);
                return !DrainIncomplete;
            }
            if (Result != null)
            {
                Result.Extra.Map["job_active_left"] = JVal.Num(left);
                Result.DrainIncomplete = true;
            }
            DrainIncomplete = true;
            DeleteProfile = false;
            return false;
        }

        public void DrainPipes()
        {
            DrainConcurrent(5, false);
        }

        public void DrainToEof()
        {
            DrainConcurrent(500, true);
        }

        public bool DrainConcurrent(int deadlineMs, bool waitUntilEof)
        {
            bool outEof = StdoutRead == IntPtr.Zero;
            bool errEof = StderrRead == IntPtr.Zero;
            Clock c = new Clock();
            byte[] buf = new byte[4096];
            char[] chars = new char[4096];
            while (c.Elapsed < Math.Max(1, deadlineMs))
            {
                if (!CheckController()) return false;
                bool progress = false;
                if (!outEof)
                {
                    progress |= PumpAvailable(StdoutRead, OutSan, OutDec, OutBuf, buf, chars, ref OutTruncated, ref outEof);
                }
                if (!errEof)
                {
                    progress |= PumpAvailable(StderrRead, ErrSan, ErrDec, ErrBuf, buf, chars, ref ErrTruncated, ref errEof);
                }
                if (Channel != null) Channel.Pump();
                if (outEof && errEof)
                {
                    FlushDecoder(OutDec, OutSan, OutBuf, chars, ref OutTruncated);
                    FlushDecoder(ErrDec, ErrSan, ErrBuf, chars, ref ErrTruncated);
                    DrainIncomplete = false;
                    return true;
                }
                if (!waitUntilEof && !progress)
                {
                    return true;
                }
                if (!progress)
                {
                    System.Threading.Thread.Sleep(5);
                }
            }
            if (waitUntilEof && !(outEof && errEof))
            {
                DrainIncomplete = true;
                if (Result != null)
                {
                    Result.DrainIncomplete = true;
                    Result.Extra.Map["drain_incomplete"] = JVal.Bool(true);
                    Result.Extra.Map["stdout_eof"] = JVal.Bool(outEof);
                    Result.Extra.Map["stderr_eof"] = JVal.Bool(errEof);
                }
                return false;
            }
            return true;
        }

        static bool PumpAvailable(IntPtr h, OutputSanitizer san, Decoder dec, StringBuilder dest, byte[] buf, char[] chars, ref bool truncated, ref bool eof)
        {
            if (h == IntPtr.Zero)
            {
                eof = true;
                return false;
            }
            uint avail;
            if (!Native.PeekNamedPipe(h, IntPtr.Zero, 0, IntPtr.Zero, out avail, IntPtr.Zero))
            {
                int e = Marshal.GetLastWin32Error();
                if (e == Native.ERROR_BROKEN_PIPE || e == Native.ERROR_NO_DATA ||
                    e == Native.ERROR_PIPE_NOT_CONNECTED || e == Native.ERROR_INVALID_HANDLE)
                {
                    eof = true;
                }
                return false;
            }
            if (avail == 0)
            {
                return false;
            }
            uint take = avail;
            if (take > (uint)buf.Length)
            {
                take = (uint)buf.Length;
            }
            uint n;
            if (!Native.ReadFile(h, buf, take, out n, IntPtr.Zero) || n == 0)
            {
                int e = Marshal.GetLastWin32Error();
                if (n == 0 || e == Native.ERROR_BROKEN_PIPE || e == Native.ERROR_NO_DATA)
                {
                    eof = true;
                }
                return false;
            }
            int got = dec.GetChars(buf, 0, (int)n, chars, 0);
            if (got > 0)
            {
                AppendSanitized(san, dest, new string(chars, 0, got), ref truncated);
            }
            return true;
        }

        static void FlushDecoder(Decoder dec, OutputSanitizer san, StringBuilder dest, char[] chars, ref bool truncated)
        {
            int bytesUsed;
            int charsUsed;
            bool completed;
            byte[] empty = new byte[1];
            dec.Convert(empty, 0, 0, chars, 0, chars.Length, true, out bytesUsed, out charsUsed, out completed);
            if (charsUsed > 0)
            {
                AppendSanitized(san, dest, new string(chars, 0, charsUsed), ref truncated);
            }
        }

        static void AppendSanitized(OutputSanitizer san, StringBuilder dest, string raw, ref bool truncated)
        {
            string clean = san.Push(raw);
            int room = Constants.StdoutMaxBytes - dest.Length;
            if (room <= 0)
            {
                truncated = true;
                return;
            }
            if (clean.Length > room)
            {
                dest.Append(clean.Substring(0, room));
                truncated = true;
                return;
            }
            dest.Append(clean);
        }

        public void CopyIo(LaunchResult result)
        {
            if (result == null)
            {
                return;
            }
            result.Stdout = OutBuf.ToString();
            result.Stderr = ErrBuf.ToString();
            result.StdoutTruncated = OutTruncated;
            result.StderrTruncated = ErrTruncated;
            result.DrainIncomplete = DrainIncomplete;
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            KillTree();
            // An empty job alone does not prove that a failed-to-assign suspended process exited.
            bool processExited = Process == IntPtr.Zero || Native.WaitForSingleObject(Process, 2000) == Native.WAIT_OBJECT_0;
            bool treeExited = WaitJobIdle(3000);
            if (!processExited || !treeExited)
            {
                DeleteProfile = false;
                if (Result != null) {
                    Result.Ok = false;
                    Result.Extra.Map["cleanup_required"] = JVal.Bool(true);
                    Result.Extra.Map["process_exit_verified"] = JVal.Bool(processExited);
                    Result.Extra.Map["job_tree_idle"] = JVal.Bool(treeExited);
                }
                // Retain profile, station, lease and handles. Never remove network constraints on uncertainty.
                return;
            }
            if (Lease != null)
            {
                string closeErr;
                bool closed;
                if (FilterWorld != null)
                {
                    closed = Lease.CloseSessionWithWorld(FilterWorld, out closeErr);
                }
                else
                {
                    closed = Lease.CloseSession(out closeErr);
                }
                if (Result != null)
                {
                    Result.Extra.Map["lease_close"] = JVal.Bool(closed);
                    if (!closed)
                    {
                        Result.Extra.Map["cleanup_required"] = JVal.Bool(true);
                        Result.Extra.Map["lease_close_error"] = JVal.Str(closeErr ?? "");
                    }
                }
                if (!closed)
                {
                    DeleteProfile = false;
                }
                if (!closed) return; // CloseSession is authoritative; do not retry cleanup via Dispose.
                Lease.Dispose();
                Lease = null;
                Job = IntPtr.Zero;
            }
            if (Controller != null)
            {
                Controller.Dispose();
                Controller = null;
            }
            ClosePipe(ref StdinWrite);
            ClosePipe(ref StdoutRead);
            ClosePipe(ref StderrRead);
            CloseChildPipeEnds();
            if (Caps != null)
            {
                Caps.Dispose();
                Caps = null;
            }
            if (Station != null)
            {
                Station.Dispose();
                Station = null;
            }
            if (Thread != IntPtr.Zero)
            {
                Native.CloseHandle(Thread);
                Thread = IntPtr.Zero;
            }
            if (Process != IntPtr.Zero)
            {
                Native.CloseHandle(Process);
                Process = IntPtr.Zero;
            }
            if (Job != IntPtr.Zero)
            {
                if (!JobBorrowed)
                {
                    Native.CloseHandle(Job);
                }
                Job = IntPtr.Zero;
            }
            if (Env != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Env);
                Env = IntPtr.Zero;
            }
            if (Ac != null)
            {
                int hr = 0;
                if (DeleteProfile)
                {
                    hr = Ac.DeleteIfOwned();
                }
                if (Result != null)
                {
                    Result.Extra.Map["profile_delete_hr"] = JVal.Str("0x" + hr.ToString("X8"));
                    Result.Extra.Map["profile_deleted"] = JVal.Bool(DeleteProfile && hr == 0);
                }
                Ac.Dispose();
                Ac = null;
            }
        }

        public void CloseChildPipeEnds()
        {
            ClosePipe(ref ChildStdin);
            ClosePipe(ref ChildStdout);
            ClosePipe(ref ChildStderr);
        }

        static void ClosePipe(ref IntPtr h)
        {
            if (h != IntPtr.Zero)
            {
                Native.CloseHandle(h);
                h = IntPtr.Zero;
            }
        }
    }
}
