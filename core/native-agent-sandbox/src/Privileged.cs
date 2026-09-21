using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NativeAgentSandbox
{
    internal sealed class PayloadToken : IDisposable
    {
        public IntPtr Primary;
        public IntPtr Impersonation;
        public string UserSid = "";
        public uint SessionId;
        public bool ElevationFlag;
        public int ElevationType;
        public bool AdminEnabled;
        bool disposed;

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (Impersonation != IntPtr.Zero)
            {
                Native.CloseHandle(Impersonation);
                Impersonation = IntPtr.Zero;
            }
            if (Primary != IntPtr.Zero)
            {
                Native.CloseHandle(Primary);
                Primary = IntPtr.Zero;
            }
        }
    }

    internal sealed class TokenSnapshot
    {
        public bool QueriesOk;
        public string QueryError = "";
        public int ElevationType;
        public bool Elevated;
        public bool AdminEnabled;
        public uint SessionId;
        public string UserSid = "";
        public bool IsAppContainer;
        public string PackageSid = "";
        public bool InJob;
    }

    internal static class TokenBridge
    {
        public static JVal InspectCurrent()
        {
            JVal o = JVal.Obj();
            IntPtr tok;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE, out tok))
            {
                o.Map["error"] = JVal.Str("OpenProcessToken win32=" + Marshal.GetLastWin32Error());
                o.Map["queries_ok"] = JVal.Bool(false);
                o.Map["linked_usable_as_payload"] = JVal.Bool(false);
                return o;
            }
            try
            {
                TokenSnapshot cur;
                if (!TrySnapshot(tok, out cur))
                {
                    o.Map["queries_ok"] = JVal.Bool(false);
                    o.Map["error"] = JVal.Str(cur.QueryError);
                    o.Map["linked_usable_as_payload"] = JVal.Bool(false);
                    return o;
                }
                bool inJob;
                Native.IsProcessInJob(Native.GetCurrentProcess(), IntPtr.Zero, out inJob);
                cur.InJob = inJob;
                FillInspect(o, cur, "");
                o.Map["queries_ok"] = JVal.Bool(true);
                IntPtr linked;
                int lerr;
                bool got = TryLinkedToken(tok, out linked, out lerr);
                o.Map["linked_token_present"] = JVal.Bool(got);
                o.Map["linked_token_win32"] = JVal.Num(lerr);
                if (!got)
                {
                    o.Map["linked_query_ok"] = JVal.Bool(false);
                    o.Map["linked_usable_as_payload"] = JVal.Bool(false);
                    return o;
                }
                try
                {
                    TokenSnapshot lim;
                    if (!TrySnapshot(linked, out lim))
                    {
                        o.Map["linked_query_ok"] = JVal.Bool(false);
                        o.Map["linked_error"] = JVal.Str(lim.QueryError);
                        o.Map["linked_usable_as_payload"] = JVal.Bool(false);
                        return o;
                    }
                    o.Map["linked_query_ok"] = JVal.Bool(true);
                    FillInspect(o, lim, "linked_");
                    o.Map["linked_usable_as_payload"] = JVal.Bool(IsUsableLimitedPayload(cur, lim));
                    return o;
                }
                finally
                {
                    Native.CloseHandle(linked);
                }
            }
            finally
            {
                Native.CloseHandle(tok);
            }
        }

        static void FillInspect(JVal o, TokenSnapshot s, string prefix)
        {
            o.Map[prefix + "elevation_type"] = JVal.Num(s.ElevationType);
            o.Map[prefix + "elevation_type_name"] = JVal.Str(ElevationName(s.ElevationType));
            o.Map[prefix + "token_is_elevated"] = JVal.Bool(s.Elevated);
            o.Map[prefix + "session_id"] = JVal.Num(s.SessionId);
            o.Map[prefix + "user_sid_len"] = JVal.Num(s.UserSid == null ? 0 : s.UserSid.Length);
            o.Map[prefix + "admin_sid_enabled"] = JVal.Bool(s.AdminEnabled);
            o.Map[prefix + "is_appcontainer"] = JVal.Bool(s.IsAppContainer);
            o.Map[prefix + "package_sid_len"] = JVal.Num(s.PackageSid == null ? 0 : s.PackageSid.Length);
            o.Map[prefix + "in_job"] = JVal.Bool(s.InJob);
        }

        public static bool IsUsableLimitedPayload(TokenSnapshot current, TokenSnapshot linked)
        {
            if (current == null || linked == null || !current.QueriesOk || !linked.QueriesOk)
            {
                return false;
            }
            if (current.ElevationType != Native.TokenElevationTypeFull)
            {
                return false;
            }
            if (linked.ElevationType != Native.TokenElevationTypeLimited)
            {
                return false;
            }
            if (linked.Elevated || linked.AdminEnabled)
            {
                return false;
            }
            if (string.IsNullOrEmpty(current.UserSid) || string.IsNullOrEmpty(linked.UserSid))
            {
                return false;
            }
            if (!string.Equals(current.UserSid, linked.UserSid, StringComparison.Ordinal))
            {
                return false;
            }
            if (current.SessionId != linked.SessionId)
            {
                return false;
            }
            return true;
        }

        public static bool CurrentLooksElevated()
        {
            IntPtr tok;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE, out tok))
            {
                return true;
            }
            try
            {
                TokenSnapshot s;
                if (!TrySnapshot(tok, out s))
                {
                    return true;
                }
                return s.ElevationType == Native.TokenElevationTypeFull || s.Elevated;
            }
            finally
            {
                Native.CloseHandle(tok);
            }
        }

        public static bool TryAcquireLimitedPayload(out PayloadToken payload, out string error, out int win32)
        {
            payload = null;
            error = "";
            win32 = 0;
            IntPtr cur;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(),
                Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE | Native.TOKEN_ASSIGN_PRIMARY, out cur))
            {
                win32 = Marshal.GetLastWin32Error();
                error = "OpenProcessToken win32=" + win32;
                return false;
            }
            try
            {
                TokenSnapshot curSnap;
                if (!TrySnapshot(cur, out curSnap))
                {
                    error = "current_token_query_failed " + curSnap.QueryError;
                    win32 = Native.ERROR_ACCESS_DENIED;
                    return false;
                }
                if (curSnap.ElevationType != Native.TokenElevationTypeFull)
                {
                    error = "requires_admin: current token is not TokenElevationTypeFull (" + curSnap.ElevationType + ")";
                    win32 = Native.ERROR_ACCESS_DENIED;
                    return false;
                }
                IntPtr linked;
                int lerr;
                if (!TryLinkedToken(cur, out linked, out lerr) || linked == IntPtr.Zero)
                {
                    win32 = lerr;
                    error = "linked_token_missing win32=" + lerr;
                    return false;
                }
                try
                {
                    TokenSnapshot linkedSnap;
                    if (!TrySnapshot(linked, out linkedSnap))
                    {
                        error = "linked_token_query_failed " + linkedSnap.QueryError;
                        win32 = Native.ERROR_ACCESS_DENIED;
                        return false;
                    }
                    if (!IsUsableLimitedPayload(curSnap, linkedSnap))
                    {
                        error = "linked_token_not_usable_limited_payload";
                        win32 = Native.ERROR_ACCESS_DENIED;
                        return false;
                    }
                    IntPtr primary;
                    if (!Native.DuplicateTokenEx(linked,
                        Native.TOKEN_ASSIGN_PRIMARY | Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY | Native.TOKEN_IMPERSONATE,
                        IntPtr.Zero, Native.SecurityImpersonation, Native.TokenPrimary, out primary) || primary == IntPtr.Zero)
                    {
                        win32 = Marshal.GetLastWin32Error();
                        error = "DuplicateTokenEx primary win32=" + win32;
                        return false;
                    }
                    IntPtr impersonation;
                    if (!Native.DuplicateTokenEx(linked,
                        Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY | Native.TOKEN_IMPERSONATE,
                        IntPtr.Zero, Native.SecurityImpersonation, Native.TokenImpersonation, out impersonation) ||
                        impersonation == IntPtr.Zero)
                    {
                        win32 = Marshal.GetLastWin32Error();
                        Native.CloseHandle(primary);
                        error = "DuplicateTokenEx impersonation win32=" + win32;
                        return false;
                    }
                    TokenSnapshot paySnap;
                    if (!TrySnapshot(primary, out paySnap) || !IsUsableLimitedPayload(curSnap, paySnap))
                    {
                        Native.CloseHandle(primary);
                        Native.CloseHandle(impersonation);
                        error = "duplicated_primary_not_verified_limited";
                        win32 = Native.ERROR_ACCESS_DENIED;
                        return false;
                    }
                    payload = new PayloadToken();
                    payload.Primary = primary;
                    payload.Impersonation = impersonation;
                    payload.UserSid = paySnap.UserSid;
                    payload.SessionId = paySnap.SessionId;
                    payload.ElevationFlag = paySnap.Elevated;
                    payload.ElevationType = paySnap.ElevationType;
                    payload.AdminEnabled = paySnap.AdminEnabled;
                    return true;
                }
                finally
                {
                    Native.CloseHandle(linked);
                }
            }
            finally
            {
                Native.CloseHandle(cur);
            }
        }

        public static bool TrySnapshot(IntPtr tok, out TokenSnapshot s)
        {
            s = new TokenSnapshot();
            s.Elevated = true;
            s.AdminEnabled = true;
            int et;
            bool elev;
            bool admin;
            uint sess;
            string user;
            if (!QueryElevationType(tok, out et))
            {
                s.QueryError = "TokenElevationType";
                return false;
            }
            if (!QueryElevated(tok, out elev))
            {
                s.QueryError = "TokenElevation";
                return false;
            }
            if (!QueryAdminEnabled(tok, out admin))
            {
                s.QueryError = "CheckTokenMembership";
                return false;
            }
            if (!QuerySessionId(tok, out sess))
            {
                s.QueryError = "TokenSessionId";
                return false;
            }
            if (!QueryUserSid(tok, out user) || string.IsNullOrEmpty(user))
            {
                s.QueryError = "TokenUser";
                return false;
            }
            bool isAc;
            string pkg;
            QueryAppContainer(tok, out isAc, out pkg);
            s.QueriesOk = true;
            s.ElevationType = et;
            s.Elevated = elev;
            s.AdminEnabled = admin;
            s.SessionId = sess;
            s.UserSid = user;
            s.IsAppContainer = isAc;
            s.PackageSid = pkg ?? "";
            s.InJob = false;
            return true;
        }

        static string ElevationName(int et)
        {
            if (et == Native.TokenElevationTypeDefault) return "Default";
            if (et == Native.TokenElevationTypeFull) return "Full";
            if (et == Native.TokenElevationTypeLimited) return "Limited";
            return et.ToString();
        }

        static bool QueryElevationType(IntPtr tok, out int et)
        {
            et = 0;
            IntPtr mem = Marshal.AllocHGlobal(4);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenElevationType, mem, 4, out ret))
                {
                    return false;
                }
                et = Marshal.ReadInt32(mem);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        static bool QueryElevated(IntPtr tok, out bool elev)
        {
            elev = true;
            int size = Marshal.SizeOf(typeof(Native.TOKEN_ELEVATION));
            IntPtr mem = Marshal.AllocHGlobal(size);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenElevation, mem, (uint)size, out ret))
                {
                    return false;
                }
                Native.TOKEN_ELEVATION te = (Native.TOKEN_ELEVATION)Marshal.PtrToStructure(mem, typeof(Native.TOKEN_ELEVATION));
                elev = te.TokenIsElevated != 0;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        static bool QuerySessionId(IntPtr tok, out uint sid)
        {
            sid = 0;
            IntPtr mem = Marshal.AllocHGlobal(4);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenSessionId, mem, 4, out ret))
                {
                    return false;
                }
                sid = (uint)Marshal.ReadInt32(mem);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        static bool QueryUserSid(IntPtr tok, out string sid)
        {
            sid = "";
            uint need;
            Native.GetTokenInformation(tok, Native.TokenUser, IntPtr.Zero, 0, out need);
            if (need == 0 || need > 4096)
            {
                return false;
            }
            IntPtr mem = Marshal.AllocHGlobal((int)need);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenUser, mem, need, out ret))
                {
                    return false;
                }
                Native.TOKEN_USER tu = (Native.TOKEN_USER)Marshal.PtrToStructure(mem, typeof(Native.TOKEN_USER));
                return Native.TrySidToString(tu.User.Sid, out sid) && !string.IsNullOrEmpty(sid);
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        static bool QueryAdminEnabled(IntPtr tok, out bool enabled)
        {
            enabled = true;
            uint cb = 256;
            IntPtr sid = Marshal.AllocHGlobal((int)cb);
            IntPtr imp = IntPtr.Zero;
            try
            {
                if (!Native.CreateWellKnownSid(Native.WinBuiltinAdministratorsSid, IntPtr.Zero, sid, ref cb))
                {
                    return false;
                }
                bool member;
                if (Native.CheckTokenMembership(tok, sid, out member))
                {
                    enabled = member;
                    return true;
                }
                if (!Native.DuplicateTokenEx(tok, Native.TOKEN_QUERY | Native.TOKEN_IMPERSONATE, IntPtr.Zero,
                    Native.SecurityImpersonation, Native.TokenImpersonation, out imp) || imp == IntPtr.Zero)
                {
                    return false;
                }
                if (!Native.CheckTokenMembership(imp, sid, out member))
                {
                    return false;
                }
                enabled = member;
                return true;
            }
            finally
            {
                if (imp != IntPtr.Zero)
                {
                    Native.CloseHandle(imp);
                }
                Marshal.FreeHGlobal(sid);
            }
        }

        static void QueryAppContainer(IntPtr tok, out bool isAc, out string pkg)
        {
            isAc = false;
            pkg = "";
            IntPtr flag = Marshal.AllocHGlobal(4);
            try
            {
                uint ret;
                if (Native.GetTokenInformation(tok, Native.TokenIsAppContainer, flag, 4, out ret))
                {
                    isAc = Marshal.ReadInt32(flag) != 0;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(flag);
            }
            uint need;
            Native.GetTokenInformation(tok, Native.TokenAppContainerSid, IntPtr.Zero, 0, out need);
            if (need == 0 || need > 4096)
            {
                return;
            }
            IntPtr mem = Marshal.AllocHGlobal((int)need);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenAppContainerSid, mem, need, out ret))
                {
                    return;
                }
                Native.TOKEN_APPCONTAINER_INFORMATION info =
                    (Native.TOKEN_APPCONTAINER_INFORMATION)Marshal.PtrToStructure(mem, typeof(Native.TOKEN_APPCONTAINER_INFORMATION));
                if (info.TokenAppContainer != IntPtr.Zero)
                {
                    Native.TrySidToString(info.TokenAppContainer, out pkg);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        static bool TryLinkedToken(IntPtr tok, out IntPtr linked, out int win32)
        {
            linked = IntPtr.Zero;
            win32 = 0;
            int size = Marshal.SizeOf(typeof(Native.TOKEN_LINKED_TOKEN));
            IntPtr mem = Marshal.AllocHGlobal(size);
            try
            {
                uint ret;
                if (!Native.GetTokenInformation(tok, Native.TokenLinkedToken, mem, (uint)size, out ret))
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                Native.TOKEN_LINKED_TOKEN lt = (Native.TOKEN_LINKED_TOKEN)Marshal.PtrToStructure(mem, typeof(Native.TOKEN_LINKED_TOKEN));
                linked = lt.LinkedToken;
                return linked != IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(mem);
            }
        }
    }

    internal static class SessionFiles
    {
        public static bool HasReparseInAncestry(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path))
                {
                    return true;
                }
                string full = Path.GetFullPath(path);
                while (!string.IsNullOrEmpty(full))
                {
                    if (File.Exists(full) || Directory.Exists(full))
                    {
                        FileAttributes a = File.GetAttributes(full);
                        if ((a & FileAttributes.ReparsePoint) != 0)
                        {
                            return true;
                        }
                    }
                    string parent = Path.GetDirectoryName(full);
                    if (string.IsNullOrEmpty(parent) || string.Equals(parent, full, StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    full = parent;
                }
                return false;
            }
            catch
            {
                return true;
            }
        }

        public static void MustRevert()
        {
            if (!Native.RevertToSelf())
            {
                Environment.FailFast("RevertToSelf failed win32=" + Marshal.GetLastWin32Error());
            }
        }

        public static bool TryCreateDirectory(IntPtr impersonation, string path, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(path))
            {
                error = "empty_path";
                return false;
            }
            if (impersonation == IntPtr.Zero)
            {
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                Directory.CreateDirectory(path);
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_after_create";
                    return false;
                }
                return true;
            }
            if (!Native.ImpersonateLoggedOnUser(impersonation))
            {
                error = "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                Directory.CreateDirectory(path);
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_after_create";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = TextUtil.Sanitize(ex.Message);
                return false;
            }
            finally
            {
                MustRevert();
            }
        }

        public static bool TryCopyFile(IntPtr impersonation, string src, string dst, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(dst))
            {
                error = "empty_path";
                return false;
            }
            if (impersonation == IntPtr.Zero)
            {
                if (HasReparseInAncestry(src) || HasReparseInAncestry(Path.GetDirectoryName(dst)))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                File.Copy(src, dst, true);
                return true;
            }
            return CopyFileImpersonated(impersonation, src, dst, out error);
        }

        public static bool CopyFileImpersonated(IntPtr impersonation, string src, string dst, out string error)
        {
            error = "";
            if (impersonation == IntPtr.Zero)
            {
                error = "no_impersonation_token";
                return false;
            }
            if (!Native.ImpersonateLoggedOnUser(impersonation))
            {
                error = "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (HasReparseInAncestry(src) || HasReparseInAncestry(Path.GetDirectoryName(dst)))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                File.Copy(src, dst, true);
                return true;
            }
            catch (Exception ex)
            {
                error = TextUtil.Sanitize(ex.Message);
                return false;
            }
            finally
            {
                MustRevert();
            }
        }

        public static bool ReadAllTextImpersonated(IntPtr impersonation, string path, out string text, out string error)
        {
            text = "";
            error = "";
            if (impersonation == IntPtr.Zero)
            {
                error = "no_impersonation_token";
                return false;
            }
            if (!Native.ImpersonateLoggedOnUser(impersonation))
            {
                error = "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                FileInfo fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > Constants.JsonMaxBytes)
                {
                    error = "config_missing_or_too_large";
                    return false;
                }
                text = File.ReadAllText(path, Encoding.UTF8);
                return true;
            }
            catch (Exception ex)
            {
                error = TextUtil.Sanitize(ex.Message);
                return false;
            }
            finally
            {
                MustRevert();
            }
        }

        public static bool WriteAllTextImpersonated(IntPtr impersonation, string path, string content, out string error)
        {
            error = "";
            if (impersonation == IntPtr.Zero)
            {
                error = "no_impersonation_token";
                return false;
            }
            if (!Native.ImpersonateLoggedOnUser(impersonation))
            {
                error = "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (HasReparseInAncestry(Path.GetDirectoryName(path)))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                File.WriteAllText(path, content ?? "", new UTF8Encoding(false));
                return true;
            }
            catch (Exception ex)
            {
                error = TextUtil.Sanitize(ex.Message);
                return false;
            }
            finally
            {
                MustRevert();
            }
        }

        public static bool FileExistsImpersonated(IntPtr impersonation, string path, out string error)
        {
            error = "";
            if (impersonation == IntPtr.Zero)
            {
                return File.Exists(path);
            }
            if (!Native.ImpersonateLoggedOnUser(impersonation))
            {
                error = "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (HasReparseInAncestry(path))
                {
                    error = "reparse_point_refused";
                    return false;
                }
                return File.Exists(path);
            }
            finally
            {
                MustRevert();
            }
        }
    }

    internal static class PrivilegedInit
    {
        public const bool ExecutePayloadImplemented = true;

        public static int Run(string[] args)
        {
            bool execute = Args.HasFlag(args, "--execute-payload");
            if (!execute)
            {
                JVal plan = BuildDryPlan();
                Console.Write(Json.Stringify(plan));
                string resultPath = Args.Get(args, "--result");
                if (!string.IsNullOrEmpty(resultPath) && !TokenBridge.CurrentLooksElevated())
                {
                    try
                    {
                        string dir = Path.GetDirectoryName(resultPath);
                        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !SessionFiles.HasReparseInAncestry(dir))
                        {
                            File.WriteAllText(resultPath, Json.Stringify(plan), new UTF8Encoding(false));
                        }
                    }
                    catch
                    {
                    }
                }
                return 0;
            }
            return ExecutePayload(args);
        }

        public static JVal BuildDryPlan()
        {
            JVal o = JVal.Obj();
            o.Map["mode"] = JVal.Str("dry-plan");
            o.Map["will_not_auto_runas"] = JVal.Bool(true);
            o.Map["execute_payload_implemented"] = JVal.Bool(true);
            o.Map["execute_payload_self_elevation"] = JVal.Bool(false);
            o.Map["brokered_wfp"] = JVal.Str("not_connected");
            o.Map["token_probe_readonly"] = TokenBridge.InspectCurrent();
            o.Map["exe_sha256"] = JVal.Str(FileSha256(Assembly.GetExecutingAssembly().Location));
            o.Map["admin_invocation_dry_plan"] = JVal.Str("not_to_run_before_root_final_review");
            o.Map["admin_invocation_execute"] = JVal.Str("not_to_run_before_root_final_review");
            JVal missing = JVal.Arr();
            JVal inspect = o.Get("token_probe_readonly");
            if (inspect.GetInt("elevation_type", 0) != Native.TokenElevationTypeFull)
            {
                missing.Items.Add(JVal.Str("TokenElevationTypeFull (current process is not elevated)"));
            }
            if (!inspect.GetBool("linked_usable_as_payload", false))
            {
                missing.Items.Add(JVal.Str("usable limited linked token (all queries ok, same TokenUser/SessionId, TokenElevationType=Limited, TokenElevation=false, Admin SID not enabled)"));
            }
            missing.Items.Add(JVal.Str("named CreateWindowStation CWF_CREATE_ONLY (Administrators); not run in this dry-plan"));
            missing.Items.Add(JVal.Str("CreateProcessAsUserW + already-enabled SE_INCREASE_QUOTA (this path does not AdjustTokenPrivileges)"));
            missing.Items.Add(JVal.Str("WFP OwnedNetworkJobLease (not connected)"));
            o.Map["missing_capabilities"] = missing;
            JVal objs = JVal.Arr();
            objs.Items.Add(JVal.Str("AppContainer profile nmzp.agent.<nonce> (CreateAppContainerProfile S_OK only, while impersonating limited user)"));
            objs.Items.Add(JVal.Str("Job Local\\nmzp.agent.<nonce>.job exclusive DACL SYSTEM/BA; ERROR_ALREADY_EXISTS refused"));
            objs.Items.Add(JVal.Str("WindowStation nmzpsta<nonce> CWF_CREATE_ONLY; desktop nmzpdesk<nonce>; min user32 rights; no WINSTA_ACCESSCLIPBOARD/READSCREEN"));
            objs.Items.Add(JVal.Str("Mandatory label LW on new objects only; never WinSta0"));
            objs.Items.Add(JVal.Str("Session staging under limited-user temp nmzp-nas-sess-<nonce>; copy/write via ImpersonateLoggedOnUser(limited)"));
            o.Map["objects_would_create"] = objs;
            o.Map["objects_created"] = JVal.Arr();
            o.Map["zero_object_mutations"] = JVal.Bool(true);
            o.Map["payload_requirements"] = JVal.Str("CreateProcessAsUserW(limited primary)+LPAC+suspended+sealed job; TokenElevationType=Limited; TokenElevation=false");
            o.Map["result_path_elevated_ignored"] = JVal.Bool(TokenBridge.CurrentLooksElevated());
            return o;
        }

        static int ExecutePayload(string[] args)
        {
            PayloadToken payload;
            string acqErr;
            int acqWin;
            if (!TokenBridge.TryAcquireLimitedPayload(out payload, out acqErr, out acqWin))
            {
                JVal o = JVal.Obj();
                o.Map["ok"] = JVal.Bool(false);
                o.Map["error_code"] = JVal.Str("requires_admin");
                o.Map["error"] = JVal.Str(acqErr);
                o.Map["win32"] = JVal.Num(acqWin);
                o.Map["zero_object_mutations"] = JVal.Bool(true);
                o.Map["execute_payload_implemented"] = JVal.Bool(true);
                Console.Write(Json.Stringify(o));
                return 3;
            }
            SyntheticStation station = null;
            AppContainerSession ac = null;
            LaunchRequest request = null;
            try
            {
                return ExecuteWithLimited(payload, args, ref station, ref ac, ref request);
            }
            finally
            {
                if (station != null)
                {
                    station.Dispose();
                }
                if (ac != null)
                {
                    ac.DeleteIfOwned();
                    ac.Dispose();
                }
                if (request != null) {
                    if (request.Channel != null) request.Channel.Dispose();
                    if (request.OwnedStation != null) request.OwnedStation.Dispose();
                    if (request.ExistingAc != null) { request.ExistingAc.DeleteIfOwned(); request.ExistingAc.Dispose(); }
                    if (request.ExistingLease != null) request.ExistingLease.Dispose();
                }
                payload.Dispose();
            }
        }

        static int ExecuteWithLimited(PayloadToken payload, string[] args, ref SyntheticStation station, ref AppContainerSession ac, ref LaunchRequest request)
        {
            string configPath = Args.Get(args, "--config");
            string resultPath = Args.Get(args, "--result");
            if (string.IsNullOrEmpty(configPath))
            {
                return ExecFail("config_missing", "execute-payload requires --config", 2, payload, null);
            }
            string json;
            string ioErr;
            if (!SessionFiles.ReadAllTextImpersonated(payload.Impersonation, configPath, out json, out ioErr))
            {
                return ExecFail("config_read", ioErr, 2, payload, null);
            }
            LaunchRequest req;
            try
            {
                req = Config.FromJson(json);
            }
            catch (Exception ex)
            {
                return ExecFail("config_invalid", TextUtil.Sanitize(ex.Message), 2, payload, null);
            }
            request = req;
            req.Level = SandboxLevel.Production;
            req.PayloadToken = payload.Primary;
            req.ImpersonationToken = payload.Impersonation;
            req.PrivilegedSession = true;
            req.ExclusiveJobDacl = true;
            req.UseRegistryReadCapability = true;

            if (req.Grok != null) {
                try { req.Channel = ControllerChannel.Connect(req); }
                catch { return ExecFail("controller_channel", "controller handshake failed", 5, payload, null); }
            }
            string nonce = TextUtil.NewNonce();
            string sessDir = null;
            string setupCode = "";
            string setupErr = "";
            int setupWin = 0;
            if (!Native.ImpersonateLoggedOnUser(payload.Impersonation))
            {
                return ExecFail("impersonate", "ImpersonateLoggedOnUser win32=" + Marshal.GetLastWin32Error(), 5, payload, null);
            }
            try
            {
                string temp = Path.GetTempPath();
                sessDir = Path.Combine(temp, "nmzp-nas-sess-" + nonce.Substring(0, 16));
                if (SessionFiles.HasReparseInAncestry(temp))
                {
                    setupCode = "session_dir";
                    setupErr = "reparse_point_refused";
                    setupWin = 5;
                }
                else
                {
                    Directory.CreateDirectory(sessDir);
                    Directory.CreateDirectory(Path.Combine(sessDir, "app"));
                    if (SessionFiles.HasReparseInAncestry(sessDir))
                    {
                        setupCode = "session_dir";
                        setupErr = "reparse_after_create";
                        setupWin = 5;
                    }
                    else
                    {
                        string acErr;
                        int acWin;
                        acWin = 0;
                        if (string.Equals(req.NetworkMode, "brokered", StringComparison.OrdinalIgnoreCase)) {
                            Nmzp.NativeEgressFilter.OwnedNetworkJobLease lease;
                            if (Nmzp.NativeEgressFilter.OwnedNetworkJobLease.TryCreate(out lease, out acErr)) {
                                req.ExistingLease = lease;
                                ac = AppContainerSession.BorrowFromLease(lease, out acErr);
                            }
                        } else ac = AppContainerSession.CreateUnique(out acErr, out acWin);
                        if (ac == null)
                        {
                            setupCode = "appcontainer_profile";
                            setupErr = acErr;
                            setupWin = acWin;
                        }
                        else if (string.IsNullOrEmpty(ac.Folder) || string.IsNullOrEmpty(ac.SidText))
                        {
                            setupCode = "appcontainer_folder";
                            setupErr = "empty folder or sid";
                        }
                        else
                        {
                            Directory.CreateDirectory(ac.Folder);
                            Directory.CreateDirectory(Path.Combine(ac.Folder, "app"));
                            Directory.CreateDirectory(Path.Combine(ac.Folder, "workspace"));
                            if (!File.Exists(req.Executable))
                            {
                                setupCode = "executable_missing";
                                setupErr = "executable not found under limited token";
                                setupWin = 2;
                            }
                            else
                            {
                                string staged = Path.Combine(ac.Folder, "app", Path.GetFileName(req.Executable));
                                if (SessionFiles.HasReparseInAncestry(req.Executable) ||
                                    SessionFiles.HasReparseInAncestry(Path.GetDirectoryName(staged)))
                                {
                                    setupCode = "exe_copy";
                                    setupErr = "reparse_point_refused";
                                    setupWin = 5;
                                }
                                else
                                {
                                    File.Copy(req.Executable, staged, true);
                                    req.Executable = staged;
                                    req.WorkingDirectory = Path.GetDirectoryName(staged);
                                    if (req.Grok != null) req.Grok.Stage(req, ac.Folder);
                                    req.CopyExeToProfile = false;
                                    req.ExistingAc = ac;
                                    ac = null;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                setupCode = "session_setup";
                setupErr = TextUtil.Sanitize(ex.GetType().Name + " " + ex.Message);
                setupWin = 1;
            }
            finally
            {
                SessionFiles.MustRevert();
            }
            if (!string.IsNullOrEmpty(setupCode))
            {
                return ExecFail(setupCode, setupErr, setupWin, payload, sessDir);
            }

            req.SessionDirectory = sessDir;
            string staName = "nmzpsta" + nonce.Substring(0, 8);
            string deskName = "nmzpdesk" + nonce.Substring(0, 8);
            string staErr;
            string pkgSid = req.ExistingAc != null ? req.ExistingAc.SidText : "";
            station = SyntheticStation.TryCreateNamedOwned(staName, deskName, payload.UserSid, pkgSid, out staErr);
            if (station == null)
            {
                if (req.ExistingAc != null)
                {
                    req.ExistingAc.DeleteIfOwned();
                    req.ExistingAc.Dispose();
                    req.ExistingAc = null;
                }
                return ExecFail("winsta_create", staErr, 5, payload, sessDir);
            }
            req.OwnedStation = station;
            station = null;

            LaunchResult launched = Supervisor.Launch(req, null);
            JVal body = launched.ToJson();
            if (req.Channel != null) { body.Map["stdout"]=JVal.Str(""); body.Map["stderr"]=JVal.Str(""); }
            body.Map["payload_token_elevation_type"] = JVal.Num(payload.ElevationType);
            body.Map["payload_token_is_elevated"] = JVal.Bool(payload.ElevationFlag);
            body.Map["payload_admin_sid_enabled"] = JVal.Bool(payload.AdminEnabled);
            body.Map["payload_session_id"] = JVal.Num(payload.SessionId);
            body.Map["payload_user_sid_len"] = JVal.Num(payload.UserSid == null ? 0 : payload.UserSid.Length);
            body.Map["execute_payload_implemented"] = JVal.Bool(true);
            if (req.Channel != null) {
                req.Channel.Pump();
                JVal done=JVal.Obj(); done.Map["type"]=JVal.Str("result"); done.Map["result"]=body;
                req.Channel.Send(done); req.Channel.Flush();
            }
            string outJson = Json.Stringify(body);
            Console.Write(outJson);
            string sessResult = Path.Combine(sessDir, "result.json");
            string werr;
            SessionFiles.WriteAllTextImpersonated(payload.Impersonation, sessResult, outJson, out werr);
            if (!string.IsNullOrEmpty(resultPath) && TextUtil.PathIsUnder(resultPath, sessDir))
            {
                SessionFiles.WriteAllTextImpersonated(payload.Impersonation, resultPath, outJson, out werr);
            }
            if (!launched.Ok)
            {
                return string.Equals(launched.ErrorCode, "brokered_filter_not_installed", StringComparison.Ordinal) ? 3 : 1;
            }
            return launched.ExitCode == 0 ? 0 : 1;
        }

        static int ExecFail(string code, string error, int win32, PayloadToken payload, string sessDir)
        {
            JVal o = LaunchResult.Fail(code, error, win32).ToJson();
            o.Map["execute_payload_implemented"] = JVal.Bool(true);
            o.Map["payload_token_is_elevated"] = JVal.Bool(payload != null && payload.ElevationFlag);
            string json = Json.Stringify(o);
            Console.Write(json);
            if (payload != null && payload.Impersonation != IntPtr.Zero && !string.IsNullOrEmpty(sessDir) && Directory.Exists(sessDir))
            {
                string werr;
                SessionFiles.WriteAllTextImpersonated(payload.Impersonation, Path.Combine(sessDir, "result.json"), json, out werr);
            }
            return string.Equals(code, "requires_admin", StringComparison.Ordinal) ? 3 : 1;
        }

        public static string FileSha256(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                return "";
            }
            using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
            {
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    StringBuilder sb = new StringBuilder(hash.Length * 2);
                    for (int i = 0; i < hash.Length; i++)
                    {
                        sb.Append(hash[i].ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
        }

        public static bool CopyFileImpersonated(IntPtr impersonation, string src, string dst, out string error)
        {
            return SessionFiles.CopyFileImpersonated(impersonation, src, dst, out error);
        }
    }
}
