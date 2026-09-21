using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Nmzp.NativeEgressFilter;

namespace NativeAgentSandbox
{
    internal sealed class ControllerLifetime : IDisposable
    {
        public IntPtr Handle;
        public int Pid;
        public long CreationTime;
        bool disposed;

        public static bool TryOpen(int pid, long creationTime, int payloadPid, out ControllerLifetime ctrl, out string error)
        {
            ctrl = null;
            error = "";
            int self = Native.GetCurrentProcessId();
            if (pid <= 0)
            {
                error = "controller_pid";
                return false;
            }
            if (pid == self)
            {
                error = "controller_is_self";
                return false;
            }
            if (payloadPid > 0 && pid == payloadPid)
            {
                error = "controller_is_payload";
                return false;
            }
            uint access = Native.PROCESS_QUERY_LIMITED_INFORMATION | Native.SYNCHRONIZE;
            IntPtr h = Native.OpenProcess(access, false, pid);
            if (h == IntPtr.Zero)
            {
                h = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.SYNCHRONIZE, false, pid);
            }
            if (h == IntPtr.Zero)
            {
                error = "OpenProcess controller win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            Native.FILETIME create, exit, kernel, user;
            if (!Native.GetProcessTimes(h, out create, out exit, out kernel, out user))
            {
                int e = Marshal.GetLastWin32Error();
                Native.CloseHandle(h);
                error = "GetProcessTimes win32=" + e;
                return false;
            }
            long got = Native.FileTimeInt64(create);
            if (got != creationTime)
            {
                Native.CloseHandle(h);
                error = "controller_creation_time_mismatch";
                return false;
            }
            if (Native.WaitForSingleObject(h, 0) == Native.WAIT_OBJECT_0)
            {
                Native.CloseHandle(h);
                error = "controller_not_alive";
                return false;
            }
            string identErr;
            if (!SameUnelevatedIdentity(h, out identErr))
            {
                Native.CloseHandle(h);
                error = identErr;
                return false;
            }
            ControllerLifetime c = new ControllerLifetime();
            c.Handle = h;
            c.Pid = pid;
            c.CreationTime = creationTime;
            ctrl = c;
            return true;
        }

        public static bool TryReadCreationTime(IntPtr process, out long creationTime, out string error)
        {
            creationTime = 0;
            error = "";
            if (process == IntPtr.Zero)
            {
                error = "controller_handle";
                return false;
            }
            Native.FILETIME create, exit, kernel, user;
            if (!Native.GetProcessTimes(process, out create, out exit, out kernel, out user))
            {
                error = "GetProcessTimes win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            creationTime = Native.FileTimeInt64(create);
            return creationTime > 0;
        }

        public bool IsAlive()
        {
            if (Handle == IntPtr.Zero)
            {
                return false;
            }
            uint w = Native.WaitForSingleObject(Handle, 0);
            return w != Native.WAIT_OBJECT_0 && w != Native.WAIT_FAILED;
        }

        static bool SameUnelevatedIdentity(IntPtr process, out string error)
        {
            error = "";
            IntPtr tok;
            if (!Native.OpenProcessToken(process, Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE, out tok))
            {
                error = "controller_token win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                TokenSnapshot ctrlSnap;
                if (!TokenBridge.TrySnapshot(tok, out ctrlSnap))
                {
                    error = "controller_token_query " + ctrlSnap.QueryError;
                    return false;
                }
                if (ctrlSnap.Elevated || ctrlSnap.AdminEnabled || ctrlSnap.ElevationType == Native.TokenElevationTypeFull)
                {
                    error = "controller_elevated";
                    return false;
                }
                IntPtr selfTok;
                if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY | Native.TOKEN_DUPLICATE, out selfTok))
                {
                    error = "self_token win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                try
                {
                    TokenSnapshot selfSnap;
                    if (!TokenBridge.TrySnapshot(selfTok, out selfSnap))
                    {
                        error = "self_token_query";
                        return false;
                    }
                    if (string.IsNullOrEmpty(selfSnap.UserSid) ||
                        !string.Equals(selfSnap.UserSid, ctrlSnap.UserSid, StringComparison.Ordinal))
                    {
                        error = "controller_user_mismatch";
                        return false;
                    }
                    if (selfSnap.SessionId != ctrlSnap.SessionId)
                    {
                        error = "controller_session_mismatch";
                        return false;
                    }
                    return true;
                }
                finally
                {
                    Native.CloseHandle(selfTok);
                }
            }
            finally
            {
                Native.CloseHandle(tok);
            }
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (Handle != IntPtr.Zero)
            {
                Native.CloseHandle(Handle);
                Handle = IntPtr.Zero;
            }
        }
    }

    internal sealed class RecordingFilterWorld : IFilterWorld, IHeldJobProof
    {
        public readonly FakeHeldWorld Inner = new FakeHeldWorld();
        public readonly List<string> Trace = new List<string>();

        public string GuardError()
        {
            return Inner.GuardError();
        }

        public bool JournalRead(string journalId, out JournalRecord rec, out string error)
        {
            Trace.Add("JournalRead");
            return Inner.JournalRead(journalId, out rec, out error);
        }

        public bool JournalWriteDurable(JournalRecord rec, out string error)
        {
            Trace.Add("JournalWriteDurable");
            return Inner.JournalWriteDurable(rec, out error);
        }

        public bool JournalDelete(string journalId, out string error)
        {
            Trace.Add("JournalDelete");
            return Inner.JournalDelete(journalId, out error);
        }

        public bool JournalExists(string journalId)
        {
            return Inner.JournalExists(journalId);
        }

        public bool ProviderGet(out SharedObjectInfo info)
        {
            return Inner.ProviderGet(out info);
        }

        public uint ProviderAdd()
        {
            Trace.Add("ProviderAdd");
            return Inner.ProviderAdd();
        }

        public bool SubLayerGet(out SharedObjectInfo info)
        {
            return Inner.SubLayerGet(out info);
        }

        public uint SubLayerAdd()
        {
            Trace.Add("SubLayerAdd");
            return Inner.SubLayerAdd();
        }

        public bool FilterGet(Guid key, out FilterSnap snap)
        {
            return Inner.FilterGet(key, out snap);
        }

        public uint FilterAdd(PlannedFilter planned, out ulong id)
        {
            Trace.Add("FilterAdd");
            return Inner.FilterAdd(planned, out id);
        }

        public uint FilterDelete(Guid key)
        {
            Trace.Add("FilterDelete");
            return Inner.FilterDelete(key);
        }

        public ExemptionEntry[] ExemptionRead()
        {
            return Inner.ExemptionRead();
        }

        public bool ExemptionWrite(ExemptionEntry[] entries, out string error)
        {
            Trace.Add("ExemptionWrite");
            return Inner.ExemptionWrite(entries, out error);
        }

        public bool ProveJobEmpty(string jobName, string packageSid, out string error, out JobScanStats stats)
        {
            Trace.Add("ProveJobEmpty");
            return Inner.ProveJobEmpty(jobName, packageSid, out error, out stats);
        }

        public bool TryHeldTreeProof(out string error, out JobScanStats stats)
        {
            Trace.Add("TryHeldTreeProof");
            return Inner.TryHeldTreeProof(out error, out stats);
        }
    }

    internal static class LeaseNetwork
    {
        public static bool PrepareGuarded(OwnedNetworkJobLease lease, int port, IFilterWorld world, LaunchRequest req, out string error)
        {
            error = "";
            if (lease == null)
            {
                error = "lease_missing";
                return false;
            }
            if (world != null)
            {
                return lease.PrepareNetworkWithWorld(port, world, out error);
            }
            if (!NetworkFilterBroker.RealApplyEnabledThisBuild) { error = "owned_wfp_build_not_enabled"; return false; }
            if (req == null || !req.PrivilegedSession || req.PayloadToken == IntPtr.Zero || req.ImpersonationToken == IntPtr.Zero ||
                !TokenBridge.CurrentLooksElevated() || lease.State != OwnedSessionState.Bound) {
                error = "owned_wfp_privileged_binding_required"; return false;
            }
            // Same held lease that verified the suspended LPAC token and job membership.
            // PrepareNetwork performs admin checks, transaction/readback and sets NetworkReady only on verified success.
            return lease.PrepareNetwork(port, out error);
        }
    }
}

namespace NativeAgentSandbox
{
    // Internal delegates permit pure tests; no delegate or proof flag is accepted by Config.FromJson.
    internal static class ResumeBarrier
    {
        public static bool TryResume(Func<bool> proofs, Func<bool> controllerAlive, Func<uint> resume, out uint previous, out string error)
        {
            previous = uint.MaxValue;
            error = "resume_proof_failed";
            try {
                if (!proofs()) return false;
                if (!controllerAlive()) { error = "controller_exited"; return false; }
                previous = resume();
                if (previous != 1) { error = "unexpected_suspend_count"; return false; }
                error = "";
                return true;
            } catch { error = "resume_check_failed"; return false; }
        }
    }
}
