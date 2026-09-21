// OwnedNetworkJobLease: same-assembly session API for the native supervisor.
// Standalone CLI apply/cleanup is unchanged (global unknown => inconclusive).
// Factory only creates a new nmzp.agent.<nonce> profile (S_OK) and a new named job
// (ERROR_ALREADY_EXISTS rejected). No AcceptExisting, no trusted JSON switch.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

namespace Nmzp.NativeEgressFilter
{
    internal enum OwnedSessionState
    {
        Created = 0,
        Bound = 1,
        NetworkReady = 2,
        Closed = 3,
        Faulted = 4
    }

    internal sealed class OwnedNetworkJobLease : IDisposable
    {
        const uint JobQuery = 0x0004;
        const uint JobSetAttributes = 0x0002;
        const uint JobTerminate = 0x0008;
        const uint JobAssign = 0x0001;
        const uint WriteDac = 0x00040000;
        const uint ErrorAlreadyExists = 183;
        const int SeGroupEnabled = 0x00000004;
        const int SeGroupDenyOnly = 0x00000010;
        const int TokenElevation = 20;
        const int TokenGroups = 2;
        const int WaitTimeoutMs = 8000;

        string profileName;
        string packageSid;
        string jobName;
        string folder;
        IntPtr job;
        IntPtr packageSidPtr;
        OwnedSessionState state;
        bool networkModified;
        bool disposed;
        FilterPlan preparedPlan;
        string creatorUserSid;
        uint creatorSessionId;
        readonly object gate = new object();

        OwnedNetworkJobLease() { }

        public string ProfileName { get { return profileName; } }
        public string PackageSid { get { return packageSid; } }
        public string JobName { get { return jobName; } }
        public string ProfileFolder { get { return folder; } }
        public OwnedSessionState State { get { return state; } }
        public bool NetworkModified { get { return networkModified; } }

        public IntPtr DangerousGetJobHandle()
        {
            if (state == OwnedSessionState.Closed || job == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            return job;
        }

        // BindSuspendedProcess verifies job membership, package SID, LPAC, same user/session, elevation.
        // It does not query CREATE_SUSPENDED; supervisor must pass a handle from its own suspended create.

        public static bool TryCreate(out OwnedNetworkJobLease lease, out string error)
        {
            lease = null;
            error = null;
            string nonce = NewNonce();
            string name = Names.ProfilePrefix + nonce;
            if (!Names.ProfileOk(name))
            {
                error = "profile_name";
                return false;
            }
            string jn = "Local\\nmzp.agent." + nonce + ".job";
            IntPtr sid = IntPtr.Zero;
            int hr = SessionNative.CreateAppContainerProfile(name, name, "nmzp-owned-session", IntPtr.Zero, 0, out sid);
            if (hr != 0 || sid == IntPtr.Zero)
            {
                error = "create_profile_hr=0x" + hr.ToString("X8");
                if (sid != IntPtr.Zero) SessionNative.FreeSid(sid);
                return false;
            }
            string sidText;
            if (!Native.TrySidToString(sid, out sidText) || !sidText.StartsWith("S-1-15-2-", StringComparison.Ordinal))
            {
                SessionNative.FreeSid(sid);
                SessionNative.DeleteAppContainerProfile(name);
                error = "profile_sid";
                return false;
            }
            string folder;
            if (!TryFolder(sidText, out folder, out error))
            {
                SessionNative.FreeSid(sid);
                SessionNative.DeleteAppContainerProfile(name);
                return false;
            }
            string creator;
            uint sessionId;
            if (!ReadCreatorIdentity(out creator, out sessionId, out error))
            {
                SessionNative.FreeSid(sid);
                SessionNative.DeleteAppContainerProfile(name);
                return false;
            }
            IntPtr job;
            if (!CreateJobWithRestrictedSd(jn, creator, out job, out error))
            {
                SessionNative.FreeSid(sid);
                SessionNative.DeleteAppContainerProfile(name);
                return false;
            }
            if (!SetAndReadbackLimits(job, out error) || !SetAndReadbackUi(job, out error))
            {
                SessionNative.CloseHandle(job);
                SessionNative.FreeSid(sid);
                SessionNative.DeleteAppContainerProfile(name);
                return false;
            }
            OwnedNetworkJobLease l = new OwnedNetworkJobLease();
            l.profileName = name;
            l.packageSid = sidText;
            l.jobName = jn;
            l.folder = folder;
            l.job = job;
            l.packageSidPtr = sid;
            l.creatorUserSid = creator;
            l.creatorSessionId = sessionId;
            l.state = OwnedSessionState.Created;
            lease = l;
            return true;
        }

        public bool BindSuspendedProcess(IntPtr process, out string error)
        {
            error = null;
            lock (gate)
            {
                if (state != OwnedSessionState.Created)
                {
                    error = "lease_bind_wrong_state";
                    if (state != OwnedSessionState.Faulted && state != OwnedSessionState.Closed) state = OwnedSessionState.Faulted;
                    return false;
                }
                if (process == IntPtr.Zero)
                {
                    error = "lease_bind_handle";
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                if (!ReadbackLimitsOk(job, out error) || !ReadbackUiOk(job, out error))
                {
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                bool inJob;
                if (!SessionNative.IsProcessInJob(process, job, out inJob) || !inJob)
                {
                    error = "lease_not_in_job";
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                if (!VerifyPayloadToken(process, out error))
                {
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                state = OwnedSessionState.Bound;
                return true;
            }
        }

        // SelfTest only. Does not inspect a process or prove CREATE_SUSPENDED.
        internal bool EnterBoundForSelfTest(out string error)
        {
            error = null;
            lock (gate)
            {
                if (state != OwnedSessionState.Created)
                {
                    error = "lease_bind_wrong_state";
                    return false;
                }
                if (!ReadbackLimitsOk(job, out error) || !ReadbackUiOk(job, out error))
                {
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                state = OwnedSessionState.Bound;
                return true;
            }
        }

        public bool PrepareNetwork(int gatewayPort, out string error)
        {
            return PrepareNetworkCore(gatewayPort, null, out error);
        }

        internal bool PrepareNetworkWithWorld(int gatewayPort, IFilterWorld world, out string error)
        {
            return PrepareNetworkCore(gatewayPort, world, out error);
        }

        bool PrepareNetworkCore(int gatewayPort, IFilterWorld world, out string error)
        {
            error = null;
            lock (gate)
            {
                if (state != OwnedSessionState.Bound)
                {
                    error = "lease_prepare_not_bound";
                    return false;
                }
                if (gatewayPort < 1 || gatewayPort > 65535)
                {
                    error = "gatewayPort";
                    return false;
                }
                FilterSpec spec = new FilterSpec();
                spec.ProfileName = profileName;
                spec.GatewayAddress = "127.0.0.1";
                spec.GatewayPort = gatewayPort;
                FilterPlan plan = Planner.Build(spec, packageSid);
                preparedPlan = plan;
                networkModified = true;
                MachineResult mr;
                if (world == null)
                {
                    if (!Native.IsElevatedAdmin())
                    {
                        networkModified = false;
                        preparedPlan = null;
                        error = "requires_admin";
                        return false;
                    }
                    RealFilterWorld real = null;
                    try
                    {
                        real = new RealFilterWorld(plan);
                        mr = NetworkInstall.Run(real, plan, Native.CurrentUserSid() ?? "unknown");
                    }
                    catch (Exception ex)
                    {
                        error = "prepare_exception:" + ex.GetType().Name;
                        state = OwnedSessionState.Faulted;
                        return false;
                    }
                    finally
                    {
                        if (real != null) real.Dispose();
                    }
                }
                else
                {
                    mr = NetworkInstall.Run(world, plan, Native.CurrentUserSid() ?? "unknown");
                }
                if (mr == null || !mr.Ok || !mr.Verified)
                {
                    error = (mr != null && mr.Error != null) ? mr.Error : "prepare_network_failed";
                    state = OwnedSessionState.Faulted;
                    return false;
                }
                state = OwnedSessionState.NetworkReady;
                return true;
            }
        }

        public bool CloseSession(out string error)
        {
            return CloseSessionCore(null, out error);
        }

        internal bool CloseSessionWithWorld(IFilterWorld world, out string error)
        {
            return CloseSessionCore(world, out error);
        }

        bool CloseSessionCore(IFilterWorld world, out string error)
        {
            error = null;
            lock (gate)
            {
                if (state == OwnedSessionState.Closed)
                {
                    return true;
                }
                if (job != IntPtr.Zero)
                {
                    SessionNative.TerminateJobObject(job, 1);
                    if (!WaitJobEmpty(out error))
                    {
                        state = OwnedSessionState.Faulted;
                        return false;
                    }
                    string limErr;
                    if (!ReadbackLimitsOk(job, out limErr) || !ReadbackUiOk(job, out limErr))
                    {
                        error = limErr;
                        state = OwnedSessionState.Faulted;
                        return false;
                    }
                }
                if (networkModified)
                {
                    if (preparedPlan == null)
                    {
                        error = "missing_prepared_plan";
                        state = OwnedSessionState.Faulted;
                        return false;
                    }
                    FilterPlan plan = preparedPlan;
                    CleanupSpec cs = new CleanupSpec();
                    cs.ProfileName = profileName;
                    cs.JournalId = plan.JournalId;
                    cs.JobKind = "named_job";
                    cs.JobName = jobName;
                    IFilterWorld use = world;
                    LeaseCleanupWorld leaseWorld = null;
                    if (use == null)
                    {
                        if (!Native.IsElevatedAdmin())
                        {
                            error = "requires_admin";
                            state = OwnedSessionState.Faulted;
                            return false;
                        }
                        try
                        {
                            leaseWorld = new LeaseCleanupWorld(plan, this);
                            use = leaseWorld;
                        }
                        catch (Exception ex)
                        {
                            error = "cleanup_world:" + ex.GetType().Name;
                            state = OwnedSessionState.Faulted;
                            return false;
                        }
                    }
                    try
                    {
                        MachineResult mr = CleanupMachine.Run(use, plan, cs, null);
                        if (!mr.Ok || !mr.Verified)
                        {
                            error = mr.Error ?? "cleanup_failed";
                            state = OwnedSessionState.Faulted;
                            return false;
                        }
                    }
                    finally
                    {
                        if (leaseWorld != null) leaseWorld.Dispose();
                    }
                }
                if (profileName != null)
                {
                    int hr = SessionNative.DeleteAppContainerProfile(profileName);
                    if (hr != 0)
                    {
                        error = "delete_profile_hr=0x" + hr.ToString("X8");
                        state = OwnedSessionState.Faulted;
                        return false;
                    }
                }
                ReleaseJobHandle();
                state = OwnedSessionState.Closed;
                return true;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (disposed) return;
                disposed = true;
                if (state == OwnedSessionState.Closed)
                {
                    ReleaseSid();
                    return;
                }
                if (networkModified)
                {
                    string err;
                    if (!CloseSessionCore(null, out err))
                    {
                        state = OwnedSessionState.Faulted;
                        ReleaseSid();
                        return;
                    }
                }
                else
                {
                    string err;
                    CloseSessionCore(null, out err);
                }
                ReleaseSid();
            }
        }

        internal bool TryHeldTreeProof(out string error, out JobScanStats stats)
        {
            stats = new JobScanStats();
            error = null;
            if (job == IntPtr.Zero)
            {
                stats.JobMissing = true;
                error = "job_open_failed";
                return false;
            }
            stats.JobOwnerKnown = true;
            stats.JobOwnerTrusted = true;
            if (!FillHeldStats(job, stats, out error))
            {
                return false;
            }
            return true;
        }

        static bool FillHeldStats(IntPtr job, JobScanStats stats, out string error)
        {
            error = null;
            int accSize = Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
            IntPtr acc = Marshal.AllocHGlobal(accSize);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectBasicAccountingInformation, acc, (uint)accSize, IntPtr.Zero))
                {
                    error = "job_query_failed";
                    return false;
                }
                JobObjectBasicAccountingInformation info = (JobObjectBasicAccountingInformation)Marshal.PtrToStructure(acc, typeof(JobObjectBasicAccountingInformation));
                stats.ActiveProcesses = info.ActiveProcesses;
                if (info.ActiveProcesses != 0) stats.JobNotEmpty = true;
            }
            finally
            {
                Marshal.FreeHGlobal(acc);
            }
            string limErr;
            if (!ReadbackLimitsOk(job, out limErr) || !ReadbackUiOk(job, out limErr))
            {
                error = limErr;
                stats.JobBreakawayOk = true;
                return false;
            }
            stats.JobKillOnClose = true;
            stats.JobBreakawayOk = false;
            stats.JobSilentBreakawayOk = false;
            int listBytes = 8 + IntPtr.Size * 64;
            IntPtr list = Marshal.AllocHGlobal(listBytes);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectBasicProcessIdList, list, (uint)listBytes, IntPtr.Zero))
                {
                    stats.JobProcessListComplete = false;
                    error = "job_pid_list_unknown";
                    return false;
                }
                JobObjectBasicProcessIdList hdr = (JobObjectBasicProcessIdList)Marshal.PtrToStructure(list, typeof(JobObjectBasicProcessIdList));
                stats.JobAssignedProcesses = hdr.NumberOfAssignedProcesses;
                stats.JobProcessListComplete = true;
                if (hdr.NumberOfAssignedProcesses > 0) stats.JobNotEmpty = true;
            }
            finally
            {
                Marshal.FreeHGlobal(list);
            }
            return true;
        }

        bool WaitJobEmpty(out string error)
        {
            error = null;
            int waited = 0;
            while (waited <= WaitTimeoutMs)
            {
                JobScanStats s = new JobScanStats();
                s.JobOwnerKnown = true;
                s.JobOwnerTrusted = true;
                string qerr;
                if (!FillHeldStats(job, s, out qerr))
                {
                    error = qerr;
                    return false;
                }
                if (JobProofEval.EvaluateHeld(s, out error))
                {
                    return true;
                }
                if (error != "job_not_empty")
                {
                    return false;
                }
                Thread.Sleep(100);
                waited += 100;
            }
            error = "job_not_empty";
            return false;
        }

        internal static class NetworkInstall
        {
            public static MachineResult Run(IFilterWorld world, FilterPlan plan, string owner)
            {
                try
                {
                    return ApplyMachine.Run(world, plan, owner, null);
                }
                catch (Exception ex)
                {
                    MachineResult r = new MachineResult();
                    r.Ok = false;
                    r.Verified = false;
                    r.Error = "prepare_exception:" + ex.GetType().Name;
                    return r;
                }
            }
        }

        bool VerifyPayloadToken(IntPtr process, out string error)
        {
            error = null;
            IntPtr token = IntPtr.Zero;
            if (!SessionNative.OpenProcessToken(process, WfpConst.TokenQuery, out token))
            {
                error = "lease_token";
                return false;
            }
            try
            {
                uint elev;
                if (!ReadTokenU32(token, WfpConst.TokenElevation, out elev, out error)) return false;
                if (elev != 0)
                {
                    error = "lease_payload_elevated";
                    return false;
                }
                uint isAc;
                if (!ReadTokenU32(token, WfpConst.TokenIsAppContainer, out isAc, out error)) return false;
                if (isAc == 0)
                {
                    error = "lease_not_appcontainer";
                    return false;
                }
                uint lpac;
                if (!ReadTokenU32(token, WfpConst.TokenIsLessPrivilegedAppContainer, out lpac, out error)) return false;
                if (lpac == 0)
                {
                    error = "lease_not_lpac";
                    return false;
                }
                uint sess;
                if (!ReadTokenU32(token, WfpConst.TokenSessionId, out sess, out error)) return false;
                if (sess != creatorSessionId)
                {
                    error = "lease_session_mismatch";
                    return false;
                }
                string userSid;
                if (!ReadTokenUserSid(token, out userSid, out error)) return false;
                if (!string.Equals(userSid, creatorUserSid, StringComparison.Ordinal))
                {
                    error = "lease_user_mismatch";
                    return false;
                }
                if (!ReadTokenAppContainerSid(token, out error)) return false;
                if (!ReadTokenGroupsNoAdminEnabled(token, out error)) return false;
                return true;
            }
            finally
            {
                SessionNative.CloseHandle(token);
            }
        }

        static bool ReadTokenU32(IntPtr token, int cls, out uint value, out string error)
        {
            value = 0;
            error = null;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                int ret;
                if (!SessionNative.GetTokenInformation(token, cls, buf, 4, out ret) || ret < 4)
                {
                    error = "lease_token_query_" + cls.ToString();
                    return false;
                }
                value = unchecked((uint)Marshal.ReadInt32(buf));
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static bool TokenInfoSize(IntPtr token, int cls, out int needed, out string error)
        {
            needed = 0;
            error = null;
            bool ok = SessionNative.GetTokenInformation(token, cls, IntPtr.Zero, 0, out needed);
            if (ok)
            {
                error = "lease_token_size_unexpected_" + cls.ToString();
                return false;
            }
            if (needed <= 0 || needed > WfpConst.MaxTokenInfoBytes)
            {
                error = "lease_token_size_" + cls.ToString();
                return false;
            }
            return true;
        }

        static bool SidInBuffer(IntPtr buf, int byteLen, IntPtr sid, out string error)
        {
            error = null;
            if (buf == IntPtr.Zero || sid == IntPtr.Zero || byteLen < 8)
            {
                error = "lease_sid_range";
                return false;
            }
            long start = buf.ToInt64();
            long end = start + byteLen;
            long addr = sid.ToInt64();
            if (addr < start || addr + 8 > end)
            {
                error = "lease_sid_range";
                return false;
            }
            int sub = Marshal.ReadByte(sid, 1) & 0xFF;
            long sidLen = 8L + 4L * sub;
            if (sub > 15 || sidAddrOverflow(addr, sidLen, end))
            {
                error = "lease_sid_range";
                return false;
            }
            if (!Native.IsValidSid(sid) || Native.GetLengthSid(sid) != (int)sidLen)
            {
                error = "lease_sid_invalid";
                return false;
            }
            return true;
        }

        static bool sidAddrOverflow(long addr, long sidLen, long end)
        {
            return sidLen <= 0 || addr + sidLen > end;
        }

        static bool ReadTokenUserSid(IntPtr token, out string sidText, out string error)
        {
            sidText = null;
            error = null;
            int needed;
            if (!TokenInfoSize(token, WfpConst.TokenUser, out needed, out error)) return false;
            IntPtr buf = Marshal.AllocHGlobal(needed);
            try
            {
                int ret;
                if (!SessionNative.GetTokenInformation(token, WfpConst.TokenUser, buf, needed, out ret) || ret < 8 || ret > needed)
                {
                    error = "lease_token_user";
                    return false;
                }
                SidAndAttributes sa = (SidAndAttributes)Marshal.PtrToStructure(buf, typeof(SidAndAttributes));
                if (!SidInBuffer(buf, ret, sa.Sid, out error))
                {
                    return false;
                }
                if (!Native.TrySidToString(sa.Sid, out sidText) || string.IsNullOrEmpty(sidText))
                {
                    error = "lease_token_user_sid";
                    return false;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        bool ReadTokenAppContainerSid(IntPtr token, out string error)
        {
            error = null;
            int needed;
            if (!TokenInfoSize(token, WfpConst.TokenAppContainerSid, out needed, out error)) return false;
            IntPtr buf = Marshal.AllocHGlobal(needed);
            try
            {
                int ret;
                if (!SessionNative.GetTokenInformation(token, WfpConst.TokenAppContainerSid, buf, needed, out ret) || ret < IntPtr.Size || ret > needed)
                {
                    error = "lease_ac_sid";
                    return false;
                }
                TokenAppContainerInformation info = (TokenAppContainerInformation)Marshal.PtrToStructure(buf, typeof(TokenAppContainerInformation));
                if (!SidInBuffer(buf, ret, info.TokenAppContainer, out error))
                {
                    return false;
                }
                if (!Native.EqualSid(info.TokenAppContainer, packageSidPtr))
                {
                    error = "lease_package_sid";
                    return false;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        internal static bool ReadTokenGroupsNoAdminEnabled(IntPtr token, out string error)
        {
            error = null;
            int needed;
            if (!TokenInfoSize(token, WfpConst.TokenGroups, out needed, out error)) return false;
            IntPtr buf = Marshal.AllocHGlobal(needed);
            IntPtr admin = IntPtr.Zero;
            try
            {
                int ret;
                if (!SessionNative.GetTokenInformation(token, WfpConst.TokenGroups, buf, needed, out ret) || ret < 8 || ret > needed)
                {
                    error = "lease_groups";
                    return false;
                }
                if (!Native.ConvertStringSidToSid(WfpConst.SidAdministrators, out admin) || admin == IntPtr.Zero)
                {
                    error = "lease_admin_sid_convert";
                    return false;
                }
                if (!Native.IsValidSid(admin))
                {
                    error = "lease_admin_sid_invalid";
                    return false;
                }
                return ParseTokenGroupsAdminEnabled(buf, ret, admin, out error);
            }
            finally
            {
                if (admin != IntPtr.Zero) Native.LocalFree(admin);
                Marshal.FreeHGlobal(buf);
            }
        }

        internal static bool ParseTokenGroupsAdminEnabled(IntPtr buf, int byteLen, IntPtr adminSid, out string error)
        {
            error = null;
            if (buf == IntPtr.Zero || byteLen < 8 || adminSid == IntPtr.Zero || !Native.IsValidSid(adminSid))
            {
                error = "lease_groups_layout";
                return false;
            }
            int count = Marshal.ReadInt32(buf);
            if (count < 0 || count > WfpConst.MaxTokenGroups)
            {
                error = "lease_groups_count";
                return false;
            }
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            long need = 8L + (long)count * stride;
            if (need > byteLen)
            {
                error = "lease_groups_overflow";
                return false;
            }
            for (int i = 0; i < count; i++)
            {
                IntPtr slot = new IntPtr(buf.ToInt64() + 8 + i * stride);
                SidAndAttributes sa = (SidAndAttributes)Marshal.PtrToStructure(slot, typeof(SidAndAttributes));
                if (!SidInBuffer(buf, byteLen, sa.Sid, out error))
                {
                    error = "lease_groups_sid_range";
                    return false;
                }
                if (Native.EqualSid(sa.Sid, adminSid))
                {
                    bool enabled = (sa.Attributes & SeGroupEnabled) != 0;
                    bool deny = (sa.Attributes & SeGroupDenyOnly) != 0;
                    if (enabled && !deny)
                    {
                        error = "lease_admin_enabled";
                        return false;
                    }
                }
            }
            return true;
        }

        static bool SetAndReadbackLimits(IntPtr job, out string error)
        {
            error = null;
            JobObjectExtendedLimitInformation lim = new JobObjectExtendedLimitInformation();
            lim.BasicLimitInformation.LimitFlags = WfpConst.JobObjectLimitKillOnJobClose;
            int size = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(lim, buf, false);
                if (!SessionNative.SetInformationJobObject(job, WfpConst.JobObjectExtendedLimitInformation, buf, (uint)size))
                {
                    error = "job_limit_set";
                    return false;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return ReadbackLimitsOk(job, out error);
        }

        static bool ReadbackLimitsOk(IntPtr job, out string error)
        {
            error = null;
            int size = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectExtendedLimitInformation, buf, (uint)size, IntPtr.Zero))
                {
                    error = "job_limit_readback";
                    return false;
                }
                JobObjectExtendedLimitInformation got = (JobObjectExtendedLimitInformation)Marshal.PtrToStructure(buf, typeof(JobObjectExtendedLimitInformation));
                uint flags = got.BasicLimitInformation.LimitFlags;
                if ((flags & WfpConst.JobObjectLimitKillOnJobClose) == 0)
                {
                    error = "job_kill_on_close_missing";
                    return false;
                }
                if ((flags & WfpConst.JobObjectLimitBreakawayOk) != 0 || (flags & WfpConst.JobObjectLimitSilentBreakawayOk) != 0)
                {
                    error = "job_breakaway_allowed";
                    return false;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static bool SetAndReadbackUi(IntPtr job, out string error)
        {
            error = null;
            JobObjectBasicUiRestrictions ui = new JobObjectBasicUiRestrictions();
            ui.UIRestrictionsClass = WfpConst.JobUiRequired;
            int size = Marshal.SizeOf(typeof(JobObjectBasicUiRestrictions));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(ui, buf, false);
                if (!SessionNative.SetInformationJobObject(job, WfpConst.JobObjectBasicUIRestrictions, buf, (uint)size))
                {
                    error = "job_ui_set";
                    return false;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return ReadbackUiOk(job, out error);
        }

        static bool ReadbackUiOk(IntPtr job, out string error)
        {
            error = null;
            int size = Marshal.SizeOf(typeof(JobObjectBasicUiRestrictions));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectBasicUIRestrictions, buf, (uint)size, IntPtr.Zero))
                {
                    error = "job_ui_readback";
                    return false;
                }
                JobObjectBasicUiRestrictions got = (JobObjectBasicUiRestrictions)Marshal.PtrToStructure(buf, typeof(JobObjectBasicUiRestrictions));
                if ((got.UIRestrictionsClass & WfpConst.JobUiRequired) != WfpConst.JobUiRequired)
                {
                    error = "job_ui_restrictions";
                    return false;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static bool CreateJobWithRestrictedSd(string jobName, string creatorSid, out IntPtr job, out string error)
        {
            job = IntPtr.Zero;
            error = null;
            if (string.IsNullOrEmpty(jobName) || string.IsNullOrEmpty(creatorSid))
            {
                error = "job_create_args";
                return false;
            }
            string sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + creatorSid + ")";
            IntPtr sd = IntPtr.Zero;
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, WfpConst.SddlRevision1, out sd, IntPtr.Zero) || sd == IntPtr.Zero)
            {
                error = "job_sd_sddl";
                return false;
            }
            try
            {
                Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = 0;
                SessionNative.SetLastError(0);
                job = SessionNative.CreateJobObject(ref sa, jobName);
                uint last = NativeLast();
                if (job == IntPtr.Zero)
                {
                    error = "job_create=" + last.ToString();
                    return false;
                }
                if (last == ErrorAlreadyExists)
                {
                    SessionNative.CloseHandle(job);
                    job = IntPtr.Zero;
                    error = "job_already_exists";
                    return false;
                }
                if (!ReadbackJobSdOk(job, creatorSid, out error))
                {
                    SessionNative.CloseHandle(job);
                    job = IntPtr.Zero;
                    return false;
                }
                return true;
            }
            finally
            {
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
            }
        }

        static bool ReadbackJobSdOk(IntPtr job, string creatorSid, out string error)
        {
            error = null;
            IntPtr owner = IntPtr.Zero;
            IntPtr group = IntPtr.Zero;
            IntPtr dacl = IntPtr.Zero;
            IntPtr sacl = IntPtr.Zero;
            IntPtr sd = IntPtr.Zero;
            IntPtr sy = IntPtr.Zero;
            IntPtr ba = IntPtr.Zero;
            IntPtr me = IntPtr.Zero;
            uint st = Native.GetSecurityInfo(
                job,
                WfpConst.SeKernelObject,
                WfpConst.OwnerSecurityInformation | WfpConst.DaclSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out sd);
            if (st != 0 || sd == IntPtr.Zero)
            {
                error = "job_sd_readback=0x" + st.ToString("X8");
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
                return false;
            }
            try
            {
                if (owner == IntPtr.Zero || !Native.IsValidSid(owner))
                {
                    error = "job_owner_missing";
                    return false;
                }
                string ownerText;
                if (!Native.TrySidToString(owner, out ownerText) || string.IsNullOrEmpty(ownerText))
                {
                    error = "job_owner_sid";
                    return false;
                }
                if (!Native.OwnerSidTrusted(ownerText))
                {
                    error = "job_owner_unknown";
                    return false;
                }
                if (dacl == IntPtr.Zero)
                {
                    error = "job_null_dacl";
                    return false;
                }
                int infoSize = Marshal.SizeOf(typeof(AclSizeInformation));
                IntPtr infoBuf = Marshal.AllocHGlobal(infoSize);
                try
                {
                    if (!Native.GetAclInformation(dacl, infoBuf, infoSize, WfpConst.AclSizeInformation))
                    {
                        error = "job_acl_info";
                        return false;
                    }
                    AclSizeInformation info = (AclSizeInformation)Marshal.PtrToStructure(infoBuf, typeof(AclSizeInformation));
                    if (info.AceCount != 3)
                    {
                        error = "job_ace_count";
                        return false;
                    }
                    if (!Native.ConvertStringSidToSid(WfpConst.SidLocalSystem, out sy) || sy == IntPtr.Zero
                        || !Native.ConvertStringSidToSid(WfpConst.SidAdministrators, out ba) || ba == IntPtr.Zero
                        || !Native.ConvertStringSidToSid(creatorSid, out me) || me == IntPtr.Zero)
                    {
                        error = "job_ace_sid_convert";
                        return false;
                    }
                    bool sawSy = false;
                    bool sawBa = false;
                    bool sawMe = false;
                    for (uint i = 0; i < info.AceCount; i++)
                    {
                        IntPtr ace;
                        if (!Native.GetAce(dacl, i, out ace) || ace == IntPtr.Zero)
                        {
                            error = "job_ace_get";
                            return false;
                        }
                        byte aceType = Marshal.ReadByte(ace, 0);
                        if (aceType != WfpConst.AccessAllowedAceType)
                        {
                            error = "job_ace_type";
                            return false;
                        }
                        ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                        if (aceSize < 8)
                        {
                            error = "job_ace_size";
                            return false;
                        }
                        IntPtr aceSid = new IntPtr(ace.ToInt64() + 8);
                        if (!Native.IsValidSid(aceSid))
                        {
                            error = "job_ace_sid";
                            return false;
                        }
                        int sidLen = Native.GetLengthSid(aceSid);
                        if (sidLen <= 0 || 8 + sidLen > aceSize)
                        {
                            error = "job_ace_sid_size";
                            return false;
                        }
                        if (Native.EqualSid(aceSid, sy)) sawSy = true;
                        else if (Native.EqualSid(aceSid, ba)) sawBa = true;
                        else if (Native.EqualSid(aceSid, me)) sawMe = true;
                        else
                        {
                            error = "job_ace_extra";
                            return false;
                        }
                    }
                    if (!sawSy || !sawBa || !sawMe)
                    {
                        error = "job_ace_missing";
                        return false;
                    }
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(infoBuf);
                }
            }
            finally
            {
                if (sy != IntPtr.Zero) Native.LocalFree(sy);
                if (ba != IntPtr.Zero) Native.LocalFree(ba);
                if (me != IntPtr.Zero) Native.LocalFree(me);
                Native.LocalFree(sd);
            }
        }

        static bool TryFolder(string sidText, out string folder, out string error)
        {
            folder = null;
            error = null;
            if (string.IsNullOrEmpty(sidText))
            {
                error = "profile_folder_sid";
                return false;
            }
            IntPtr p;
            int hr = SessionNative.GetAppContainerFolderPath(sidText, out p);
            if (hr != 0 || p == IntPtr.Zero)
            {
                error = "profile_folder_hr=0x" + hr.ToString("X8");
                return false;
            }
            try
            {
                string path = Marshal.PtrToStringUni(p);
                if (string.IsNullOrEmpty(path))
                {
                    error = "profile_folder_empty";
                    return false;
                }
                uint attrs = Native.GetFileAttributes(path);
                if (attrs == WfpConst.InvalidFileAttributes)
                {
                    error = "profile_folder_missing";
                    return false;
                }
                if (Native.FileAttrsAreReparse(attrs))
                {
                    error = "profile_folder_reparse";
                    return false;
                }
                folder = path;
                return true;
            }
            finally
            {
                SessionNative.CoTaskMemFree(p);
            }
        }

        static bool ReadCreatorIdentity(out string sid, out uint sessionId, out string error)
        {
            sid = Native.CurrentUserSid();
            sessionId = 0;
            error = null;
            if (string.IsNullOrEmpty(sid))
            {
                error = "creator_user_sid";
                return false;
            }
            if (!Native.ProcessIdToSessionId(Native.GetCurrentProcessId(), out sessionId))
            {
                error = "creator_session";
                return false;
            }
            return true;
        }

        static string NewNonce()
        {
            byte[] b = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(b);
            }
            char[] hex = new char[32];
            const string map = "0123456789abcdef";
            for (int i = 0; i < 16; i++)
            {
                hex[i * 2] = map[(b[i] >> 4) & 0xF];
                hex[i * 2 + 1] = map[b[i] & 0xF];
            }
            return new string(hex);
        }

        static uint NativeLast()
        {
            return unchecked((uint)Marshal.GetLastWin32Error());
        }

        void ReleaseJobHandle()
        {
            if (job != IntPtr.Zero)
            {
                SessionNative.CloseHandle(job);
                job = IntPtr.Zero;
            }
        }

        void ReleaseSid()
        {
            if (packageSidPtr != IntPtr.Zero)
            {
                SessionNative.FreeSid(packageSidPtr);
                packageSidPtr = IntPtr.Zero;
            }
        }
    }

    sealed class LeaseCleanupWorld : RealFilterWorld, IHeldJobProof
    {
        readonly OwnedNetworkJobLease lease;

        public LeaseCleanupWorld(FilterPlan plan, OwnedNetworkJobLease lease)
            : base(plan)
        {
            this.lease = lease;
        }

        public bool TryHeldTreeProof(out string error, out JobScanStats stats)
        {
            return lease.TryHeldTreeProof(out error, out stats);
        }
    }

    static class SessionNative
    {
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int CreateAppContainerProfile(string a, string b, string c, IntPtr caps, uint n, out IntPtr sid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int DeleteAppContainerProfile(string a);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int GetAppContainerFolderPath(string sid, out IntPtr path);

        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr p);

        [DllImport("advapi32.dll")]
        public static extern IntPtr FreeSid(IntPtr p);

        [DllImport("kernel32.dll")]
        public static extern void SetLastError(uint err);

        [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateJobObject(IntPtr a, string name);

        [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateJobObject(ref Native.SECURITY_ATTRIBUTES sa, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetInformationJobObject(IntPtr job, int cls, IntPtr info, uint len);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryInformationJobObject(IntPtr job, int cls, IntPtr info, uint len, IntPtr ret);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateJobObject(IntPtr job, uint code);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsProcessInJob(IntPtr proc, IntPtr job, out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int ret);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    }
}
