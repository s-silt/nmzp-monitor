using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Nmzp.NativeEgressFilter
{
    internal sealed class NativeBag : IDisposable
    {
        readonly List<IntPtr> items = new List<IntPtr>();
        bool disposed;

        public IntPtr Alloc(int size)
        {
            IntPtr p = Marshal.AllocHGlobal(size);
            Zero(p, size);
            items.Add(p);
            return p;
        }

        public IntPtr Uni(string s)
        {
            IntPtr p = Marshal.StringToHGlobalUni(s);
            items.Add(p);
            return p;
        }

        public IntPtr AllocSidFromString(string sidText)
        {
            IntPtr src = IntPtr.Zero;
            try
            {
                if (!Native.ConvertStringSidToSid(sidText, out src) || src == IntPtr.Zero)
                {
                    throw new InvalidOperationException("sid_convert");
                }
                int len = Native.GetLengthSid(src);
                IntPtr dst = Alloc(len);
                if (!Native.CopySid(len, dst, src))
                {
                    throw new InvalidOperationException("sid_copy");
                }
                return dst;
            }
            finally
            {
                if (src != IntPtr.Zero)
                {
                    Native.LocalFree(src);
                }
            }
        }

        static void Zero(IntPtr p, int size)
        {
            byte[] z = new byte[size];
            Marshal.Copy(z, 0, p, size);
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            for (int i = 0; i < items.Count; i++)
            {
                if (items[i] != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(items[i]);
                }
            }
            items.Clear();
        }
    }

    internal static class Engine
    {
        public static uint Open(NativeBag bag, out IntPtr engine)
        {
            engine = IntPtr.Zero;
            FwpmSession0 session = new FwpmSession0();
            session.flags = 0;
            session.txnWaitTimeoutInMSec = 10000;
            session.displayData.name = bag.Uni("NMZP native egress filter");
            IntPtr sp = bag.Alloc(WfpConst.LayoutSessionSize);
            Marshal.StructureToPtr(session, sp, false);
            return Native.FwpmEngineOpen0(null, WfpConst.RpcCAuthnWinnt, IntPtr.Zero, sp, out engine);
        }

        public static void Close(IntPtr engine)
        {
            if (engine != IntPtr.Zero)
            {
                Native.FwpmEngineClose0(engine);
            }
        }
    }

    internal static class WfpInstall
    {
        public static uint AddFilterOnly(IntPtr engine, NativeBag bag, PlannedFilter planned, IntPtr packageSid, int gatewayPort, out ulong filterId, out string error)
        {
            filterId = 0;
            error = null;
            IntPtr conds = BuildConditions(bag, planned, packageSid, gatewayPort);
            IntPtr prov = bag.Alloc(16);
            Marshal.Copy(WfpGuids.Provider.ToByteArray(), 0, prov, 16);

            FwpmFilter0 f = new FwpmFilter0();
            f.filterKey = planned.FilterKey;
            f.displayData.name = bag.Uni("NMZP " + planned.Role);
            f.flags = WfpConst.FwpmFilterFlagPersistent;
            f.providerKey = prov;
            f.layerKey = planned.LayerKey;
            f.subLayerKey = WfpGuids.SubLayer;
            f.weight.type = WfpConst.FwpUint8;
            f.weight.value = new IntPtr(planned.Weight);
            f.numFilterConditions = (uint)ConditionCount(planned);
            f.filterCondition = conds;
            f.action.type = planned.ActionType;
            IntPtr fp = bag.Alloc(WfpConst.LayoutFilterSize);
            Marshal.StructureToPtr(f, fp, false);
            uint st = Native.FwpmFilterAdd0(engine, fp, IntPtr.Zero, out filterId);
            if (st != 0)
            {
                error = "filter_add=0x" + st.ToString("X8");
            }
            return st;
        }

        static int ConditionCount(PlannedFilter planned)
        {
            return string.Equals(planned.Role, "v4_allow_tcp_gateway", StringComparison.Ordinal) ? 4 : 1;
        }

        static IntPtr BuildConditions(NativeBag bag, PlannedFilter planned, IntPtr packageSid, int gatewayPort)
        {
            int n = ConditionCount(planned);
            IntPtr arr = bag.Alloc(WfpConst.LayoutConditionSize * n);
            WriteCondition(arr, 0, WfpGuids.CondAlePackageId, WfpConst.FwpSid, packageSid);
            if (n == 4)
            {
                WriteCondition(arr, 1, WfpGuids.CondIpProtocol, WfpConst.FwpUint8, new IntPtr(WfpConst.IpProtoTcp));
                WriteCondition(arr, 2, WfpGuids.CondIpRemoteAddress, WfpConst.FwpUint32, new IntPtr(unchecked((int)WfpConst.Ipv4LoopbackHostOrder)));
                WriteCondition(arr, 3, WfpGuids.CondIpRemotePort, WfpConst.FwpUint16, new IntPtr(gatewayPort));
            }
            return arr;
        }

        static void WriteCondition(IntPtr arr, int index, Guid field, int valueType, IntPtr value)
        {
            IntPtr slot = new IntPtr(arr.ToInt64() + index * WfpConst.LayoutConditionSize);
            FwpmFilterCondition0 c = new FwpmFilterCondition0();
            c.fieldKey = field;
            c.matchType = WfpConst.FwpMatchEqual;
            c.conditionValue.type = valueType;
            c.conditionValue.value = value;
            Marshal.StructureToPtr(c, slot, false);
        }

        public static bool VerifyAll(IntPtr engine, FilterPlan plan, IntPtr packageSid, out string error)
        {
            error = null;
            for (int i = 0; i < plan.Filters.Length; i++)
            {
                PlannedFilter pf = plan.Filters[i];
                Guid key = pf.FilterKey;
                IntPtr got = IntPtr.Zero;
                uint st = Native.FwpmFilterGetByKey0(engine, ref key, out got);
                if (st != 0 || got == IntPtr.Zero)
                {
                    error = "verify_get:" + pf.Role + "=0x" + st.ToString("X8");
                    if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                    return false;
                }
                bool match = FilterIdentity.Matches(got, pf, packageSid, plan.GatewayPort, out error);
                Native.FwpmFreeMemory0(ref got);
                if (!match)
                {
                    if (error == null) error = "verify_mismatch:" + pf.Role;
                    return false;
                }
            }
            return true;
        }

        public static uint DeleteOwnFilter(IntPtr engine, JournalFilter jf, IntPtr packageSid, int gatewayPort, out string error)
        {
            error = null;
            Guid key;
            try { key = new Guid(jf.FilterKey); }
            catch
            {
                error = "bad_journal_filter_key";
                return 0xFFFFFFFF;
            }
            IntPtr got = IntPtr.Zero;
            uint st = Native.FwpmFilterGetByKey0(engine, ref key, out got);
            if (st == WfpConst.FwpENotFound || st == WfpConst.ErrorFileNotFound || st == WfpConst.ErrorNotFound)
            {
                return 0;
            }
            if (st != 0 || got == IntPtr.Zero)
            {
                error = "delete_get=0x" + st.ToString("X8");
                if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                return st;
            }
            PlannedFilter fake = new PlannedFilter();
            fake.Role = jf.Role;
            fake.FilterKey = key;
            fake.Layer = jf.Layer;
            fake.LayerKey = LayerOf(jf.Layer);
            fake.Action = jf.Action;
            fake.ActionType = string.Equals(jf.Action, "permit", StringComparison.Ordinal) ? WfpConst.FwpActionPermit : WfpConst.FwpActionBlock;
            fake.Weight = string.Equals(jf.Role, "v4_allow_tcp_gateway", StringComparison.Ordinal) ? WfpConst.WeightAllow : WfpConst.WeightBlock;
            fake.Persistent = true;
            bool match = FilterIdentity.Matches(got, fake, packageSid, gatewayPort, out error);
            Native.FwpmFreeMemory0(ref got);
            if (!match)
            {
                if (error == null) error = "delete_identity_mismatch";
                return 0xFFFFFFFF;
            }
            st = Native.FwpmFilterDeleteByKey0(engine, ref key);
            if (st == WfpConst.FwpENotFound) st = 0;
            if (st != 0) error = "delete=0x" + st.ToString("X8");
            return st;
        }

        static Guid LayerOf(string layer)
        {
            if (layer == "ALE_AUTH_CONNECT_V6") return WfpGuids.LayerAleAuthConnectV6;
            return WfpGuids.LayerAleAuthConnectV4;
        }
    }

    internal static class FilterIdentity
    {
        public static bool Matches(IntPtr filterPtr, PlannedFilter planned, IntPtr packageSid, int gatewayPort, out string error)
        {
            error = null;
            FwpmFilter0 f = (FwpmFilter0)Marshal.PtrToStructure(filterPtr, typeof(FwpmFilter0));
            if (f.filterKey != planned.FilterKey)
            {
                error = "key";
                return false;
            }
            if (f.layerKey != planned.LayerKey)
            {
                error = "layer";
                return false;
            }
            if (f.subLayerKey != WfpGuids.SubLayer)
            {
                error = "sublayer";
                return false;
            }
            if (f.providerKey == IntPtr.Zero)
            {
                error = "provider_null";
                return false;
            }
            byte[] buf = new byte[16];
            Marshal.Copy(f.providerKey, buf, 0, 16);
            if (new Guid(buf) != WfpGuids.Provider)
            {
                error = "provider";
                return false;
            }
            if ((f.flags & WfpConst.FwpmFilterFlagPersistent) == 0)
            {
                error = "not_persistent";
                return false;
            }
            if ((f.flags & WfpConst.FwpmFilterFlagClearActionRight) != 0)
            {
                error = "hard_permit_flag_set";
                return false;
            }
            if (f.action.type != planned.ActionType)
            {
                error = "action";
                return false;
            }
            if (f.numFilterConditions < 1 || f.filterCondition == IntPtr.Zero)
            {
                error = "conditions";
                return false;
            }
            bool sawSid = false;
            for (int i = 0; i < (int)f.numFilterConditions; i++)
            {
                IntPtr slot = new IntPtr(f.filterCondition.ToInt64() + i * WfpConst.LayoutConditionSize);
                FwpmFilterCondition0 c = (FwpmFilterCondition0)Marshal.PtrToStructure(slot, typeof(FwpmFilterCondition0));
                if (c.fieldKey == WfpGuids.CondAlePackageId)
                {
                    if (c.conditionValue.type != WfpConst.FwpSid || c.conditionValue.value == IntPtr.Zero)
                    {
                        error = "package_type";
                        return false;
                    }
                    if (!Native.EqualSid(c.conditionValue.value, packageSid))
                    {
                        error = "package_sid";
                        return false;
                    }
                    sawSid = true;
                }
            }
            if (!sawSid)
            {
                error = "missing_package_id";
                return false;
            }
            return true;
        }
    }

    internal static class ExemptionApi
    {
        public static bool ReadEntries(out ExemptionEntry[] entries, out string error)
        {
            entries = new ExemptionEntry[0];
            error = null;
            uint count = 0;
            IntPtr arr = IntPtr.Zero;
            uint st = Native.NetworkIsolationGetAppContainerConfig(out count, out arr);
            if (st != 0)
            {
                error = "exemption_get=0x" + st.ToString("X8");
                return false;
            }
            try
            {
                List<ExemptionEntry> list = new List<ExemptionEntry>();
                int stride = Marshal.SizeOf(typeof(SidAndAttributes));
                for (uint i = 0; i < count; i++)
                {
                    IntPtr slot = new IntPtr(arr.ToInt64() + i * stride);
                    SidAndAttributes sa = (SidAndAttributes)Marshal.PtrToStructure(slot, typeof(SidAndAttributes));
                    string text;
                    if (sa.Sid != IntPtr.Zero && Native.TrySidToString(sa.Sid, out text))
                    {
                        list.Add(new ExemptionEntry(text, sa.Attributes));
                    }
                }
                entries = ExemptionLogic.Copy(list);
                return true;
            }
            finally
            {
                FreeGet(count, arr);
            }
        }

        public static bool WriteEntries(ExemptionEntry[] entries, out string error)
        {
            error = null;
            List<IntPtr> locals = new List<IntPtr>();
            IntPtr arr = IntPtr.Zero;
            try
            {
                int n = entries == null ? 0 : entries.Length;
                if (n == 0)
                {
                    uint st0 = Native.NetworkIsolationSetAppContainerConfig(0, IntPtr.Zero);
                    if (st0 != 0)
                    {
                        error = "exemption_set=0x" + st0.ToString("X8");
                        return false;
                    }
                    return true;
                }
                int stride = Marshal.SizeOf(typeof(SidAndAttributes));
                arr = Marshal.AllocHGlobal(stride * n);
                for (int i = 0; i < n; i++)
                {
                    IntPtr sid;
                    if (!Native.ConvertStringSidToSid(entries[i].Sid, out sid) || sid == IntPtr.Zero)
                    {
                        error = "exemption_sid_convert";
                        return false;
                    }
                    locals.Add(sid);
                    SidAndAttributes sa = new SidAndAttributes();
                    sa.Sid = sid;
                    sa.Attributes = entries[i].Attributes;
                    Marshal.StructureToPtr(sa, new IntPtr(arr.ToInt64() + i * stride), false);
                }
                uint st = Native.NetworkIsolationSetAppContainerConfig((uint)n, arr);
                if (st != 0)
                {
                    error = "exemption_set=0x" + st.ToString("X8");
                    return false;
                }
                return true;
            }
            finally
            {
                for (int i = 0; i < locals.Count; i++)
                {
                    if (locals[i] != IntPtr.Zero) Native.LocalFree(locals[i]);
                }
                if (arr != IntPtr.Zero) Marshal.FreeHGlobal(arr);
            }
        }

        static void FreeGet(uint count, IntPtr arr)
        {
            if (arr == IntPtr.Zero) return;
            IntPtr heap = Native.GetProcessHeap();
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            for (uint i = 0; i < count; i++)
            {
                IntPtr slot = new IntPtr(arr.ToInt64() + i * stride);
                SidAndAttributes sa = (SidAndAttributes)Marshal.PtrToStructure(slot, typeof(SidAndAttributes));
                if (sa.Sid != IntPtr.Zero)
                {
                    Native.HeapFree(heap, 0, sa.Sid);
                }
            }
            Native.HeapFree(heap, 0, arr);
        }
    }

    internal static class JobProof
    {
        public static bool ProveEmpty(string jobName, string packageSid, out string error, out JobScanStats stats)
        {
            stats = new JobScanStats();
            error = null;
            uint access = WfpConst.JobObjectQuery | WfpConst.ReadControl;
            IntPtr job = Native.OpenJobObject(access, false, jobName);
            if (job == IntPtr.Zero)
            {
                job = Native.OpenJobObject(WfpConst.JobObjectQuery, false, jobName);
                if (job == IntPtr.Zero)
                {
                    stats.JobMissing = true;
                    error = "job_open_failed";
                    return false;
                }
                stats.JobOwnerKnown = false;
            }
            try
            {
                FillJobIdentity(job, stats);
                int size = Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    if (!Native.QueryInformationJobObject(job, WfpConst.JobObjectBasicAccountingInformation, buf, (uint)size, IntPtr.Zero))
                    {
                        error = "job_query_failed";
                        stats.JobMissing = true;
                        return false;
                    }
                    JobObjectBasicAccountingInformation info = (JobObjectBasicAccountingInformation)Marshal.PtrToStructure(buf, typeof(JobObjectBasicAccountingInformation));
                    stats.ActiveProcesses = info.ActiveProcesses;
                    if (info.ActiveProcesses != 0)
                    {
                        stats.JobNotEmpty = true;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                Native.CloseHandle(job);
            }

            if (!ScanPackage(packageSid, stats, out error))
            {
                return false;
            }
            return JobProofEval.Evaluate(stats, out error);
        }

        static void FillJobIdentity(IntPtr job, JobScanStats stats)
        {
            IntPtr owner = IntPtr.Zero;
            IntPtr group = IntPtr.Zero;
            IntPtr dacl = IntPtr.Zero;
            IntPtr sacl = IntPtr.Zero;
            IntPtr sd = IntPtr.Zero;
            uint st = Native.GetSecurityInfo(
                job,
                WfpConst.SeKernelObject,
                WfpConst.OwnerSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out sd);
            try
            {
                string sid;
                if (st == 0 && owner != IntPtr.Zero && Native.TrySidToString(owner, out sid))
                {
                    stats.JobOwnerKnown = true;
                    stats.JobOwnerTrusted = Native.OwnerSidTrusted(sid);
                }
                else
                {
                    stats.JobOwnerKnown = false;
                    stats.JobOwnerTrusted = false;
                }
            }
            finally
            {
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
            }

            int extSize = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            IntPtr ext = Marshal.AllocHGlobal(extSize);
            try
            {
                if (Native.QueryInformationJobObject(job, WfpConst.JobObjectExtendedLimitInformation, ext, (uint)extSize, IntPtr.Zero))
                {
                    JobObjectExtendedLimitInformation lim = (JobObjectExtendedLimitInformation)Marshal.PtrToStructure(ext, typeof(JobObjectExtendedLimitInformation));
                    uint flags = lim.BasicLimitInformation.LimitFlags;
                    stats.JobBreakawayOk = (flags & WfpConst.JobObjectLimitBreakawayOk) != 0;
                    stats.JobSilentBreakawayOk = (flags & WfpConst.JobObjectLimitSilentBreakawayOk) != 0;
                    stats.JobKillOnClose = (flags & WfpConst.JobObjectLimitKillOnJobClose) != 0;
                }
                else
                {
                    stats.JobBreakawayOk = true;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ext);
            }

            int listBytes = 8 + IntPtr.Size * 256;
            IntPtr list = Marshal.AllocHGlobal(listBytes);
            try
            {
                if (!Native.QueryInformationJobObject(job, WfpConst.JobObjectBasicProcessIdList, list, (uint)listBytes, IntPtr.Zero))
                {
                    int win = Marshal.GetLastWin32Error();
                    stats.JobProcessListComplete = false;
                    if ((uint)win == WfpConst.ErrorMoreData)
                    {
                        stats.JobNotEmpty = true;
                    }
                }
                else
                {
                    JobObjectBasicProcessIdList hdr = (JobObjectBasicProcessIdList)Marshal.PtrToStructure(list, typeof(JobObjectBasicProcessIdList));
                    stats.JobAssignedProcesses = hdr.NumberOfAssignedProcesses;
                    stats.JobProcessListComplete = hdr.NumberOfAssignedProcesses <= hdr.NumberOfProcessIdsInList;
                    if (hdr.NumberOfAssignedProcesses > 0) stats.JobNotEmpty = true;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(list);
            }
        }

        public static bool ScanPackage(string packageSid, JobScanStats stats, out string error)
        {
            error = null;
            IntPtr want = IntPtr.Zero;
            if (!Native.ConvertStringSidToSid(packageSid, out want) || want == IntPtr.Zero)
            {
                error = "scan_sid_convert";
                return false;
            }
            try
            {
                int[] pids = new int[16384];
                int needed;
                int bufBytes = pids.Length * 4;
                stats.BufferSlots = pids.Length;
                if (!Native.K32EnumProcesses(pids, bufBytes, out needed))
                {
                    error = "enum_processes_failed";
                    return false;
                }
                if (JobProofEval.EnumBufferFull(needed, bufBytes))
                {
                    stats.EnumTruncated = true;
                    error = "enum_processes_truncated";
                    return false;
                }
                int n = needed / 4;
                stats.PidCount = n;
                uint ourSession;
                Native.ProcessIdToSessionId(Native.GetCurrentProcessId(), out ourSession);
                for (int i = 0; i < n; i++)
                {
                    int pid = pids[i];
                    if (pid == 0 || pid == 4) continue;
                    int m;
                    int deniedClass;
                    if (!InspectPid(pid, want, ourSession, out m, out deniedClass))
                    {
                        stats.OtherUnknown++;
                        continue;
                    }
                    stats.Matches += m;
                    if (deniedClass == 1) stats.SystemDenied++;
                    else if (deniedClass == 2) stats.SessionDenied++;
                    else if (deniedClass == 3) stats.OtherUnknown++;
                }
                return true;
            }
            finally
            {
                Native.LocalFree(want);
            }
        }

        static bool InspectPid(int pid, IntPtr wantSid, uint ourSession, out int match, out int deniedClass)
        {
            match = 0;
            deniedClass = 0;
            IntPtr proc = Native.OpenProcess(WfpConst.ProcessQueryLimitedInformation, false, pid);
            if (proc == IntPtr.Zero)
            {
                uint sess;
                if (!Native.ProcessIdToSessionId(unchecked((uint)pid), out sess))
                {
                    deniedClass = 3;
                    return true;
                }
                if (sess == 0) deniedClass = 1;
                else if (sess == ourSession) deniedClass = 2;
                else deniedClass = 3;
                return true;
            }
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!Native.OpenProcessToken(proc, WfpConst.TokenQuery, out token))
                {
                    deniedClass = 3;
                    return true;
                }
                int ret;
                IntPtr dword = Marshal.AllocHGlobal(4);
                try
                {
                    if (!Native.GetTokenInformation(token, WfpConst.TokenIsAppContainer, dword, 4, out ret))
                    {
                        deniedClass = 3;
                        return true;
                    }
                    int isAc = Marshal.ReadInt32(dword);
                    if (isAc == 0)
                    {
                        return true;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(dword);
                }
                Native.GetTokenInformation(token, WfpConst.TokenAppContainerSid, IntPtr.Zero, 0, out ret);
                if (ret <= 0)
                {
                    deniedClass = 3;
                    return true;
                }
                IntPtr buf = Marshal.AllocHGlobal(ret);
                try
                {
                    if (!Native.GetTokenInformation(token, WfpConst.TokenAppContainerSid, buf, ret, out ret))
                    {
                        deniedClass = 3;
                        return true;
                    }
                    TokenAppContainerInformation info = (TokenAppContainerInformation)Marshal.PtrToStructure(buf, typeof(TokenAppContainerInformation));
                    if (info.TokenAppContainer != IntPtr.Zero && Native.EqualSid(info.TokenAppContainer, wantSid))
                    {
                        match = 1;
                    }
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                if (token != IntPtr.Zero) Native.CloseHandle(token);
                Native.CloseHandle(proc);
            }
        }
    }

    internal class RealFilterWorld : IFilterWorld, IDisposable
    {
        readonly NativeBag bag = new NativeBag();
        readonly FilterPlan plan;
        readonly IntPtr packageSid;
        IntPtr engine;
        bool engineOpen;
        ExemptionEntry[] lastRead;
        readonly string journalDir;

        public RealFilterWorld(FilterPlan plan)
        {
            this.plan = plan;
            journalDir = Names.DefaultJournalDir();
            packageSid = bag.AllocSidFromString(plan.PackageSid);
            uint st = Engine.Open(bag, out engine);
            if (st != 0)
            {
                throw new InvalidOperationException("engine_open=0x" + st.ToString("X8"));
            }
            engineOpen = true;
        }

        public string GuardError()
        {
            return null;
        }

        public bool JournalRead(string journalId, out JournalRecord rec, out string error)
        {
            return JournalIo.TryRead(Names.JournalPath(journalDir, journalId), out rec, out error);
        }

        public bool JournalWriteDurable(JournalRecord rec, out string error)
        {
            return JournalIo.DurableWrite(Names.JournalPath(journalDir, rec.JournalId), JournalIo.Serialize(rec), out error);
        }

        public bool JournalDelete(string journalId, out string error)
        {
            return JournalIo.Delete(Names.JournalPath(journalDir, journalId), out error);
        }

        public bool JournalExists(string journalId)
        {
            return File.Exists(Names.JournalPath(journalDir, journalId));
        }

        public bool ProviderGet(out SharedObjectInfo info)
        {
            info = new SharedObjectInfo();
            Guid key = WfpGuids.Provider;
            IntPtr got = IntPtr.Zero;
            uint st = Native.FwpmProviderGetByKey0(engine, ref key, out got);
            if (st != 0 || got == IntPtr.Zero)
            {
                if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                info.Found = false;
                return false;
            }
            try
            {
                FwpmProvider0 p = (FwpmProvider0)Marshal.PtrToStructure(got, typeof(FwpmProvider0));
                info.Found = true;
                info.Flags = p.flags;
                info.OwnerSid = WfpOwner(true, false);
                info.SecurityKnown = info.OwnerSid != null;
                return true;
            }
            finally
            {
                Native.FwpmFreeMemory0(ref got);
            }
        }

        public uint ProviderAdd()
        {
            FwpmProvider0 p = new FwpmProvider0();
            p.providerKey = WfpGuids.Provider;
            p.flags = WfpConst.FwpmProviderFlagPersistent;
            p.displayData.name = bag.Uni("NMZP native egress filter");
            p.displayData.description = bag.Uni("SID-exact AppContainer outbound filters");
            IntPtr pp = bag.Alloc(WfpConst.LayoutProviderSize);
            Marshal.StructureToPtr(p, pp, false);
            return Native.FwpmProviderAdd0(engine, pp, IntPtr.Zero);
        }

        public bool SubLayerGet(out SharedObjectInfo info)
        {
            info = new SharedObjectInfo();
            Guid key = WfpGuids.SubLayer;
            IntPtr got = IntPtr.Zero;
            uint st = Native.FwpmSubLayerGetByKey0(engine, ref key, out got);
            if (st != 0 || got == IntPtr.Zero)
            {
                if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                info.Found = false;
                return false;
            }
            try
            {
                FwpmSubLayer0 s = (FwpmSubLayer0)Marshal.PtrToStructure(got, typeof(FwpmSubLayer0));
                info.Found = true;
                info.Flags = s.flags;
                info.Weight = s.weight;
                if (s.providerKey != IntPtr.Zero)
                {
                    byte[] b = new byte[16];
                    Marshal.Copy(s.providerKey, b, 0, 16);
                    info.ProviderKey = new Guid(b);
                }
                info.OwnerSid = WfpOwner(false, true);
                info.SecurityKnown = info.OwnerSid != null;
                return true;
            }
            finally
            {
                Native.FwpmFreeMemory0(ref got);
            }
        }

        public uint SubLayerAdd()
        {
            IntPtr prov = bag.Alloc(16);
            Marshal.Copy(WfpGuids.Provider.ToByteArray(), 0, prov, 16);
            FwpmSubLayer0 s = new FwpmSubLayer0();
            s.subLayerKey = WfpGuids.SubLayer;
            s.flags = WfpConst.FwpmSubLayerFlagPersistent;
            s.providerKey = prov;
            s.weight = WfpConst.SubLayerWeight;
            s.displayData.name = bag.Uni("NMZP native egress sublayer");
            IntPtr sp = bag.Alloc(WfpConst.LayoutSubLayerSize);
            Marshal.StructureToPtr(s, sp, false);
            return Native.FwpmSubLayerAdd0(engine, sp, IntPtr.Zero);
        }

        public bool FilterGet(Guid key, out FilterSnap snap)
        {
            snap = new FilterSnap();
            Guid k = key;
            IntPtr got = IntPtr.Zero;
            uint st = Native.FwpmFilterGetByKey0(engine, ref k, out got);
            if (st == WfpConst.FwpENotFound || st == WfpConst.ErrorNotFound)
            {
                if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                snap.QueryOk = true;
                snap.Found = false;
                return true;
            }
            if (st != 0 || got == IntPtr.Zero)
            {
                if (got != IntPtr.Zero) Native.FwpmFreeMemory0(ref got);
                snap.QueryOk = false;
                snap.QueryError = "filter_get=0x" + st.ToString("X8");
                snap.Found = false;
                return false;
            }
            try
            {
                FwpmFilter0 f = (FwpmFilter0)Marshal.PtrToStructure(got, typeof(FwpmFilter0));
                snap.QueryOk = true;
                snap.Found = true;
                snap.FilterKey = f.filterKey;
                snap.LayerKey = f.layerKey;
                snap.SubLayerKey = f.subLayerKey;
                snap.Flags = f.flags;
                snap.ActionType = f.action.type;
                snap.WeightType = f.weight.type;
                if (f.weight.type == WfpConst.FwpUint8)
                {
                    snap.Weight = (byte)(f.weight.value.ToInt64() & 0xFF);
                }
                if (f.providerKey != IntPtr.Zero)
                {
                    byte[] b = new byte[16];
                    Marshal.Copy(f.providerKey, b, 0, 16);
                    snap.ProviderKey = new Guid(b);
                }
                ParseConditions(f, snap);
                if (!snap.QueryOk)
                {
                    return false;
                }
                return true;
            }
            finally
            {
                Native.FwpmFreeMemory0(ref got);
            }
        }

        internal static void ParseConditions(FwpmFilter0 f, FilterSnap snap)
        {
            if (f.numFilterConditions == 0)
            {
                snap.Conditions = new ConditionSpec[0];
                return;
            }
            if (f.numFilterConditions > (uint)WfpConst.MaxFilterConditions || f.filterCondition == IntPtr.Zero)
            {
                snap.QueryOk = false;
                snap.QueryError = "filter_condition_malformed";
                snap.Conditions = new ConditionSpec[0];
                return;
            }
            snap.Conditions = new ConditionSpec[f.numFilterConditions];
            for (int i = 0; i < (int)f.numFilterConditions; i++)
            {
                IntPtr slot = new IntPtr(f.filterCondition.ToInt64() + i * WfpConst.LayoutConditionSize);
                FwpmFilterCondition0 c = (FwpmFilterCondition0)Marshal.PtrToStructure(slot, typeof(FwpmFilterCondition0));
                ConditionSpec spec = new ConditionSpec();
                spec.FieldKey = c.fieldKey;
                spec.MatchType = c.matchType;
                spec.ValueType = c.conditionValue.type;
                long bits = c.conditionValue.value.ToInt64();
                if (spec.ValueType == WfpConst.FwpSid && c.conditionValue.value != IntPtr.Zero)
                {
                    string s;
                    if (Native.TrySidToString(c.conditionValue.value, out s)) spec.Sid = s;
                    if (spec.FieldKey == WfpGuids.CondAlePackageId) snap.PackageSid = spec.Sid;
                }
                else if (spec.ValueType == WfpConst.FwpUint32)
                {
                    spec.U32 = (uint)(bits & 0xFFFFFFFF);
                }
                else if (spec.ValueType == WfpConst.FwpUint16)
                {
                    spec.U16 = (ushort)(bits & 0xFFFF);
                }
                else if (spec.ValueType == WfpConst.FwpUint8)
                {
                    spec.U8 = (byte)(bits & 0xFF);
                }
                snap.Conditions[i] = spec;
            }
        }

        public uint FilterAdd(PlannedFilter planned, out ulong id)
        {
            string err;
            return WfpInstall.AddFilterOnly(engine, bag, planned, packageSid, plan.GatewayPort, out id, out err);
        }

        public uint FilterDelete(Guid key)
        {
            Guid k = key;
            return Native.FwpmFilterDeleteByKey0(engine, ref k);
        }

        public ExemptionEntry[] ExemptionRead()
        {
            ExemptionEntry[] e;
            string err;
            if (!ExemptionApi.ReadEntries(out e, out err))
            {
                lastRead = null;
                return null;
            }
            lastRead = e;
            return e;
        }

        public bool ExemptionWrite(ExemptionEntry[] entries, out string error)
        {
            ExemptionEntry[] live;
            if (!ExemptionApi.ReadEntries(out live, out error)) return false;
            if (lastRead != null && !ExemptionLogic.SameEntries(lastRead, live))
            {
                error = "exemption_concurrent_change";
                return false;
            }
            return ExemptionApi.WriteEntries(entries, out error);
        }

        public bool ProveJobEmpty(string jobName, string packageSidText, out string error, out JobScanStats stats)
        {
            return JobProof.ProveEmpty(jobName, packageSidText, out error, out stats);
        }

        string WfpOwner(bool provider, bool sublayer)
        {
            Guid key = provider ? WfpGuids.Provider : WfpGuids.SubLayer;
            IntPtr owner = IntPtr.Zero;
            IntPtr group = IntPtr.Zero;
            IntPtr dacl = IntPtr.Zero;
            IntPtr sacl = IntPtr.Zero;
            IntPtr sd = IntPtr.Zero;
            uint st;
            if (provider)
            {
                st = Native.FwpmProviderGetSecurityInfoByKey0(engine, ref key, WfpConst.OwnerSecurityInformation, out owner, out group, out dacl, out sacl, out sd);
            }
            else
            {
                st = Native.FwpmSubLayerGetSecurityInfoByKey0(engine, ref key, WfpConst.OwnerSecurityInformation, out owner, out group, out dacl, out sacl, out sd);
            }
            try
            {
                if (st != 0 || owner == IntPtr.Zero) return null;
                string s;
                if (!Native.TrySidToString(owner, out s)) return null;
                return s;
            }
            finally
            {
                if (sd != IntPtr.Zero) Native.FwpmFreeMemory0(ref sd);
            }
        }

        public void Dispose()
        {
            if (engineOpen)
            {
                Engine.Close(engine);
                engineOpen = false;
            }
            bag.Dispose();
        }
    }

    internal static class Commands
    {
        public static int PrepareOrPlan(string command, string specJson)
        {
            string layoutErr;
            if (!Native.LayoutOk(out layoutErr))
            {
                Console.WriteLine(ResultJson.Emit(false, command, false, false, false, layoutErr, null, null, null));
                return 2;
            }
            try
            {
                FilterSpec spec = SpecParser.ParseFilterSpec(specJson);
                string sid;
                string err;
                if (!Native.TryDerivePackageSid(spec.ProfileName, out sid, out err))
                {
                    Console.WriteLine(ResultJson.Emit(false, command, false, false, false, err, null, null, null));
                    return 3;
                }
                FilterPlan plan = Planner.Build(spec, sid);
                Console.WriteLine(Planner.ToRedactedJson(plan, command, true, null));
                return 0;
            }
            catch (JsonException ex)
            {
                Console.WriteLine(ResultJson.Emit(false, command, false, false, false, "spec:" + ex.Message, null, null, null));
                return 2;
            }
        }

        public static int Apply(string specJson)
        {
            string layoutErr;
            if (!Native.LayoutOk(out layoutErr))
            {
                Console.WriteLine(ResultJson.Emit(false, "apply", false, false, false, layoutErr, null, null, null));
                return 2;
            }
            FilterSpec spec;
            try
            {
                spec = SpecParser.ParseFilterSpec(specJson);
            }
            catch (JsonException ex)
            {
                Console.WriteLine(ResultJson.Emit(false, "apply", false, false, false, "spec:" + ex.Message, null, null, null));
                return 2;
            }
            if (!Native.IsElevatedAdmin())
            {
                Console.WriteLine(ResultJson.Emit(false, "apply", false, false, false, "requires_admin", null, null, Extra("mutationSum", Native.MutationSum().ToString(CultureInfo.InvariantCulture))));
                return 4;
            }

            string sid;
            string err;
            if (!Native.TryDerivePackageSid(spec.ProfileName, out sid, out err))
            {
                Console.WriteLine(ResultJson.Emit(false, "apply", false, false, false, err, null, null, null));
                return 3;
            }
            FilterPlan plan = Planner.Build(spec, sid);
            if (!JournalPathGuard.EnsureWritableStore(out err))
            {
                Fail("apply", err, plan, false, false, false, "no_wfp_mutation");
                return 5;
            }
            RealFilterWorld world = null;
            try
            {
                world = new RealFilterWorld(plan);
                MachineResult mr = ApplyMachine.Run(world, plan, Native.CurrentUserSid() ?? "unknown", null);
                Dictionary<string, string> extra = Extra("recovery", mr.Recovery ?? "none");
                extra["mutationSum"] = Native.MutationSum().ToString(CultureInfo.InvariantCulture);
                extra["state"] = mr.State ?? (mr.Journal != null ? mr.Journal.State : "");
                Console.WriteLine(ResultJson.Emit(mr.Ok, "apply", mr.Installed, mr.Verified, mr.Changed, mr.Error, plan, mr.Journal, extra));
                return mr.Ok ? 0 : 5;
            }
            catch (Exception ex)
            {
                Fail("apply", "exception:" + ex.GetType().Name, plan, false, false, Native.MutationSum() > 0, "leave_blocking_if_any");
                return 5;
            }
            finally
            {
                if (world != null) world.Dispose();
            }
        }

        public static int Cleanup(string specJson)
        {
            string layoutErr;
            if (!Native.LayoutOk(out layoutErr))
            {
                Console.WriteLine(ResultJson.Emit(false, "cleanup", false, false, false, layoutErr, null, null, null));
                return 2;
            }
            CleanupSpec spec;
            try
            {
                spec = SpecParser.ParseCleanupSpec(specJson);
            }
            catch (JsonException ex)
            {
                Console.WriteLine(ResultJson.Emit(false, "cleanup", false, false, false, "spec:" + ex.Message, null, null, null));
                return 2;
            }
            if (!Native.IsElevatedAdmin())
            {
                Console.WriteLine(ResultJson.Emit(false, "cleanup", false, false, false, "requires_admin", null, null, Extra("mutationSum", Native.MutationSum().ToString(CultureInfo.InvariantCulture))));
                return 4;
            }

            string derived;
            string err;
            if (!Native.TryDerivePackageSid(spec.ProfileName, out derived, out err))
            {
                Console.WriteLine(ResultJson.Emit(false, "cleanup", false, false, false, err, null, null, Extra("recovery", "leave_exact_sid_block_if_any")));
                return 3;
            }
            FilterSpec fs = new FilterSpec();
            fs.ProfileName = spec.ProfileName;
            fs.GatewayAddress = "127.0.0.1";
            fs.GatewayPort = 1;
            JournalRecord peek;
            string peekErr;
            string journalPath = Names.JournalPath(Names.DefaultJournalDir(), spec.JournalId);
            if (JournalIo.TryRead(journalPath, out peek, out peekErr) && peek != null)
            {
                fs.GatewayPort = peek.GatewayPort;
                if (!string.IsNullOrEmpty(peek.GatewayAddress)) fs.GatewayAddress = peek.GatewayAddress;
            }
            FilterPlan plan = Planner.Build(fs, derived);
            if (!string.Equals(plan.JournalId, spec.JournalId, StringComparison.Ordinal) && peek != null)
            {
                plan = Planner.Build(fs, peek.PackageSid);
            }
            RealFilterWorld world = null;
            try
            {
                world = new RealFilterWorld(plan);
                MachineResult mr = CleanupMachine.Run(world, plan, spec, null);
                Dictionary<string, string> extra = Extra("recovery", mr.Recovery ?? "leave_exact_sid_block");
                extra["mutationSum"] = Native.MutationSum().ToString(CultureInfo.InvariantCulture);
                extra["deletedFilters"] = mr.DeletedFilters ? "true" : "false";
                extra["journalDeleted"] = mr.JournalDeleted ? "true" : "false";
                extra["state"] = mr.State ?? "";
                Console.WriteLine(ResultJson.Emit(mr.Ok, "cleanup", mr.Installed, mr.Verified, mr.Changed, mr.Error, plan, mr.Journal, extra));
                return mr.Ok ? 0 : 5;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ResultJson.Emit(false, "cleanup", true, false, false, "exception:" + ex.GetType().Name, plan, null, Extra("recovery", "leave_exact_sid_block")));
                return 5;
            }
            finally
            {
                if (world != null) world.Dispose();
            }
        }

        public static int Status(string specJson)
        {
            string layoutErr;
            if (!Native.LayoutOk(out layoutErr))
            {
                Console.WriteLine(ResultJson.Emit(false, "status", false, false, false, layoutErr, null, null, null));
                return 2;
            }
            FilterSpec spec;
            try
            {
                spec = SpecParser.ParseFilterSpec(specJson);
            }
            catch (JsonException ex)
            {
                Console.WriteLine(ResultJson.Emit(false, "status", false, false, false, "spec:" + ex.Message, null, null, null));
                return 2;
            }
            string sid;
            string err;
            if (!Native.TryDerivePackageSid(spec.ProfileName, out sid, out err))
            {
                Console.WriteLine(ResultJson.Emit(false, "status", false, false, false, err, null, null, null));
                return 3;
            }
            FilterPlan plan = Planner.Build(spec, sid);
            string journalPath = Names.JournalPath(Names.DefaultJournalDir(), plan.JournalId);
            JournalRecord jr;
            bool haveJr = JournalIo.TryRead(journalPath, out jr, out err);
            if (!Native.IsElevatedAdmin())
            {
                Dictionary<string, string> extra = Extra("wfpQueried", "false");
                extra["journalReadable"] = haveJr ? "true" : "false";
                Console.WriteLine(ResultJson.Emit(haveJr, "status", haveJr, false, false, haveJr ? null : "journal_inaccessible_or_missing", plan, jr, extra));
                return haveJr ? 0 : 6;
            }

            IntPtr engine = IntPtr.Zero;
            NativeBag bag = new NativeBag();
            try
            {
                IntPtr packageSid = bag.AllocSidFromString(sid);
                uint st = Engine.Open(bag, out engine);
                if (st != 0)
                {
                    Console.WriteLine(ResultJson.Emit(false, "status", haveJr, false, false, "engine_open=0x" + st.ToString("X8"), plan, jr, Extra("wfpQueried", "false")));
                    return 5;
                }
                bool verified = WfpInstall.VerifyAll(engine, plan, packageSid, out err);
                ExemptionEntry[] ents;
                string e2;
                bool gotEx = ExemptionApi.ReadEntries(out ents, out e2);
                Dictionary<string, string> extra = Extra("wfpQueried", "true");
                extra["ourExemption"] = (gotEx && ExemptionLogic.Contains(ents, sid)) ? "true" : "false";
                extra["foreignExemptionCount"] = gotEx ? ExemptionLogic.PlanAdd(ents, sid, true).ForeignCount.ToString(CultureInfo.InvariantCulture) : "-1";
                extra["journalReadable"] = haveJr ? "true" : "false";
                Console.WriteLine(ResultJson.Emit(verified && haveJr, "status", haveJr && verified, verified, false, verified ? null : (err ?? "not_installed"), plan, jr, extra));
                return verified && haveJr ? 0 : 6;
            }
            finally
            {
                Engine.Close(engine);
                bag.Dispose();
            }
        }

        static Dictionary<string, string> Extra(string k, string v)
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.Ordinal);
            d[k] = v;
            return d;
        }

        static void Fail(string command, string error, FilterPlan plan, bool installed, bool verified, bool changed, string recovery)
        {
            Dictionary<string, string> extra = Extra("recovery", recovery);
            extra["mutationSum"] = Native.MutationSum().ToString(CultureInfo.InvariantCulture);
            Console.WriteLine(ResultJson.Emit(false, command, installed, verified, changed, error, plan, null, extra));
        }
    }
}
