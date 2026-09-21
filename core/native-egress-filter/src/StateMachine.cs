using System;
using System.Collections.Generic;

namespace Nmzp.NativeEgressFilter
{
    internal sealed class SharedObjectInfo
    {
        public bool Found;
        public uint Flags;
        public ushort Weight;
        public Guid ProviderKey;
        public string OwnerSid;
        public bool SecurityKnown;
    }

    internal sealed class FilterSnap
    {
        public bool QueryOk;
        public string QueryError;
        public bool Found;
        public Guid FilterKey;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public Guid ProviderKey;
        public uint Flags;
        public uint ActionType;
        public byte Weight;
        public int WeightType;
        public string PackageSid;
        public ConditionSpec[] Conditions;
    }

    internal sealed class MachineResult
    {
        public bool Ok;
        public string Error;
        public string State;
        public bool Changed;
        public bool Installed;
        public bool Verified;
        public bool FiltersMutated;
        public bool ExemptionMutated;
        public bool DeletedFilters;
        public bool JournalWritten;
        public bool JournalDeleted;
        public JournalRecord Journal;
        public string Recovery;
        public int ExemptionWrites;
    }

    internal interface IFilterWorld
    {
        string GuardError();
        bool JournalRead(string journalId, out JournalRecord rec, out string error);
        bool JournalWriteDurable(JournalRecord rec, out string error);
        bool JournalDelete(string journalId, out string error);
        bool JournalExists(string journalId);
        bool ProviderGet(out SharedObjectInfo info);
        uint ProviderAdd();
        bool SubLayerGet(out SharedObjectInfo info);
        uint SubLayerAdd();
        bool FilterGet(Guid key, out FilterSnap snap);
        uint FilterAdd(PlannedFilter planned, out ulong id);
        uint FilterDelete(Guid key);
        ExemptionEntry[] ExemptionRead();
        bool ExemptionWrite(ExemptionEntry[] entries, out string error);
        bool ProveJobEmpty(string jobName, string packageSid, out string error, out JobScanStats stats);
    }

    internal interface IHeldJobProof
    {
        bool TryHeldTreeProof(out string error, out JobScanStats stats);
    }

    internal static class FilterLookup
    {
        public static bool Try(IFilterWorld world, Guid key, out FilterSnap snap, out string error)
        {
            snap = null;
            error = null;
            bool q = world.FilterGet(key, out snap);
            if (!q || snap == null || !snap.QueryOk)
            {
                error = (snap != null && !string.IsNullOrEmpty(snap.QueryError)) ? snap.QueryError : "filter_get_failed";
                return false;
            }
            return true;
        }
    }

    internal static class SharedVerify
    {
        public static bool ProviderOk(SharedObjectInfo info, out string error)
        {
            error = null;
            if (info == null || !info.Found)
            {
                error = "provider_missing";
                return false;
            }
            if ((info.Flags & WfpConst.FwpmProviderFlagPersistent) == 0)
            {
                error = "provider_not_persistent";
                return false;
            }
            if (!info.SecurityKnown)
            {
                error = "provider_security_unknown";
                return false;
            }
            if (!Native.OwnerSidTrusted(info.OwnerSid))
            {
                error = "provider_foreign_owner";
                return false;
            }
            return true;
        }

        public static bool SubLayerOk(SharedObjectInfo info, out string error)
        {
            error = null;
            if (info == null || !info.Found)
            {
                error = "sublayer_missing";
                return false;
            }
            if ((info.Flags & WfpConst.FwpmSubLayerFlagPersistent) == 0)
            {
                error = "sublayer_not_persistent";
                return false;
            }
            if (info.Weight != WfpConst.SubLayerWeight)
            {
                error = "sublayer_weight";
                return false;
            }
            if (info.ProviderKey != WfpGuids.Provider)
            {
                error = "sublayer_provider";
                return false;
            }
            if (!info.SecurityKnown)
            {
                error = "sublayer_security_unknown";
                return false;
            }
            if (!Native.OwnerSidTrusted(info.OwnerSid))
            {
                error = "sublayer_foreign_owner";
                return false;
            }
            return true;
        }

        public static bool FilterOurs(FilterSnap snap, PlannedFilter planned, string packageSid, out string error)
        {
            error = null;
            if (snap == null || !snap.Found)
            {
                error = "filter_missing";
                return false;
            }
            if (snap.FilterKey != planned.FilterKey)
            {
                error = "filter_key";
                return false;
            }
            if (snap.LayerKey != planned.LayerKey)
            {
                error = "filter_layer";
                return false;
            }
            if (snap.SubLayerKey != WfpGuids.SubLayer)
            {
                error = "filter_sublayer";
                return false;
            }
            if (snap.ProviderKey != WfpGuids.Provider)
            {
                error = "filter_provider";
                return false;
            }
            if ((snap.Flags & WfpConst.FwpmFilterFlagPersistent) == 0)
            {
                error = "filter_not_persistent";
                return false;
            }
            if ((snap.Flags & WfpConst.FwpmFilterFlagClearActionRight) != 0)
            {
                error = "filter_hard_permit";
                return false;
            }
            if (snap.ActionType != planned.ActionType)
            {
                error = "filter_action";
                return false;
            }
            if (snap.WeightType != planned.WeightType || snap.WeightType != WfpConst.FwpUint8)
            {
                error = "filter_weight_type";
                return false;
            }
            if (snap.Weight != planned.Weight)
            {
                error = "filter_weight";
                return false;
            }
            if (planned.Expected == null || planned.Expected.Length < 1)
            {
                error = "filter_expected_empty";
                return false;
            }
            if (snap.Conditions == null || snap.Conditions.Length != planned.Expected.Length)
            {
                error = "filter_condition_count";
                return false;
            }
            for (int i = 0; i < snap.Conditions.Length; i++)
            {
                ConditionSpec got = snap.Conditions[i];
                if (got == null)
                {
                    error = "filter_condition_null";
                    return false;
                }
                if (got.MatchType != WfpConst.FwpMatchEqual)
                {
                    error = "filter_match_type";
                    return false;
                }
                if (!ConditionSpec.KnownField(got.FieldKey))
                {
                    error = "filter_condition_unknown_field";
                    return false;
                }
                if (!ConditionSpec.KnownValueType(got.ValueType))
                {
                    error = "filter_condition_unknown_type";
                    return false;
                }
            }
            bool[] used = new bool[snap.Conditions.Length];
            for (int e = 0; e < planned.Expected.Length; e++)
            {
                bool found = false;
                for (int i = 0; i < snap.Conditions.Length; i++)
                {
                    if (used[i]) continue;
                    if (ConditionSpec.Equal(planned.Expected[e], snap.Conditions[i]))
                    {
                        used[i] = true;
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    error = "filter_condition_mismatch";
                    return false;
                }
            }
            string pkg = null;
            for (int i = 0; i < snap.Conditions.Length; i++)
            {
                if (snap.Conditions[i].FieldKey == WfpGuids.CondAlePackageId)
                {
                    pkg = snap.Conditions[i].Sid;
                }
            }
            if (!string.Equals(pkg, packageSid, StringComparison.Ordinal))
            {
                error = "filter_package_sid";
                return false;
            }
            return true;
        }
    }

    internal static class ApplyMachine
    {
        public static MachineResult Run(IFilterWorld world, FilterPlan plan, string ownerSid, string stopAfter)
        {
            MachineResult r = new MachineResult();
            r.Recovery = "leave_no_exemption";
            if (world == null || plan == null)
            {
                r.Error = "machine_args";
                return r;
            }
            string g = world.GuardError();
            if (!string.IsNullOrEmpty(g))
            {
                r.Error = g;
                return r;
            }
            if (Stop(stopAfter, "guard", r)) return r;

            JournalRecord prior;
            string err;
            bool havePrior = world.JournalRead(plan.JournalId, out prior, out err);
            if (havePrior && prior != null)
            {
                if (!JournalIo.MatchesPlan(prior, plan, out err))
                {
                    r.Error = err;
                    r.Journal = prior;
                    r.Recovery = "leave_exact_sid_block";
                    return r;
                }
            }
            else if (JournalIo.IsAbsentError(err))
            {
                prior = null;
            }
            else
            {
                r.Error = string.IsNullOrEmpty(err) ? "journal_unreadable" : err;
                r.Recovery = "leave_exact_sid_block_if_any";
                return r;
            }
            if (Stop(stopAfter, "load_journal", r)) return r;

            ExemptionEntry[] ex = world.ExemptionRead();
            if (ex == null)
            {
                r.Error = "exemption_read";
                return r;
            }
            bool ownEx = JournalState.ClaimsExemption(prior);
            ExemptionMergeResult preEx = ExemptionLogic.PlanAdd(ex, plan.PackageSid, ownEx);
            if (!preEx.Ok)
            {
                r.Error = preEx.Error;
                r.Journal = prior;
                r.Recovery = "leave_exact_sid_block";
                return r;
            }
            if (Stop(stopAfter, "precheck_exemption", r)) return r;

            for (int i = 0; i < plan.Filters.Length; i++)
            {
                FilterSnap snap;
                if (!FilterLookup.Try(world, plan.Filters[i].FilterKey, out snap, out err))
                {
                    r.Error = err;
                    r.Recovery = "leave_exact_sid_block_if_any";
                    return r;
                }
                if (snap.Found)
                {
                    if (prior == null || !JournalState.AllowsResumeFilter(prior.State))
                    {
                        r.Error = "filter_exists_unknown";
                        r.Recovery = "leave_exact_sid_block_if_any";
                        return r;
                    }
                    if (!SharedVerify.FilterOurs(snap, plan.Filters[i], plan.PackageSid, out err))
                    {
                        r.Error = "filter_foreign:" + err;
                        r.Recovery = "leave_exact_sid_block_if_any";
                        return r;
                    }
                }
            }
            if (Stop(stopAfter, "precheck_filters", r)) return r;

            SharedObjectInfo prov;
            if (world.ProviderGet(out prov) && prov != null && prov.Found)
            {
                if (!SharedVerify.ProviderOk(prov, out err))
                {
                    r.Error = err;
                    return r;
                }
            }
            SharedObjectInfo sub;
            if (world.SubLayerGet(out sub) && sub != null && sub.Found)
            {
                if (!SharedVerify.SubLayerOk(sub, out err))
                {
                    r.Error = err;
                    return r;
                }
            }
            if (Stop(stopAfter, "precheck_shared", r)) return r;

            JournalRecord rec = prior;
            if (rec == null || rec.State == JournalState.Planned || string.IsNullOrEmpty(rec.State))
            {
                rec = JournalIo.FromPlan(plan, ownerSid, JournalState.Planned);
                JournalIo.PreserveOwnership(prior, rec);
                if (!world.JournalWriteDurable(rec, out err))
                {
                    r.Error = err ?? "journal_write_failed";
                    r.Recovery = "no_wfp_mutation";
                    return r;
                }
                r.JournalWritten = true;
                r.Journal = rec;
            }
            else
            {
                rec = CloneJournal(prior);
                JournalIo.PreserveOwnership(prior, rec);
                r.Journal = rec;
            }
            if (Stop(stopAfter, "write_planned", r)) return r;

            if (!EnsureShared(world, true, out err))
            {
                r.Error = err;
                r.Changed = r.FiltersMutated;
                r.Journal = rec;
                return r;
            }
            if (!EnsureShared(world, false, out err))
            {
                r.Error = err;
                r.Changed = r.FiltersMutated;
                r.Journal = rec;
                return r;
            }
            if (Stop(stopAfter, "ensure_shared", r)) return r;

            if (rec.State == JournalState.Planned || rec.State == JournalState.FiltersInstalled
                || rec.State == JournalState.ExemptionPending || rec.State == JournalState.Ready)
            {
                for (int i = 0; i < plan.Filters.Length; i++)
                {
                    FilterSnap snap;
                    if (!FilterLookup.Try(world, plan.Filters[i].FilterKey, out snap, out err))
                    {
                        r.Error = err;
                        r.Journal = rec;
                        r.Recovery = "leave_exact_sid_block_if_any";
                        return r;
                    }
                    if (snap.Found)
                    {
                        if (!JournalState.AllowsResumeFilter(rec.State))
                        {
                            r.Error = "filter_exists_unknown";
                            r.Journal = rec;
                            r.Recovery = "leave_exact_sid_block_if_any";
                            return r;
                        }
                        if (!SharedVerify.FilterOurs(snap, plan.Filters[i], plan.PackageSid, out err))
                        {
                            r.Error = "filter_foreign:" + err;
                            r.Journal = rec;
                            return r;
                        }
                        continue;
                    }
                    ulong id;
                    uint st = world.FilterAdd(plan.Filters[i], out id);
                    if (st == WfpConst.FwpEAlreadyExists)
                    {
                        r.Error = "filter_already_exists_unverified";
                        r.Journal = rec;
                        r.Recovery = "leave_exact_sid_block_if_any";
                        return r;
                    }
                    if (st != 0)
                    {
                        r.Error = "filter_add=0x" + st.ToString("X8");
                        r.Journal = rec;
                        r.FiltersMutated = true;
                        r.Changed = true;
                        return r;
                    }
                    r.FiltersMutated = true;
                    r.Changed = true;
                }
            }
            if (Stop(stopAfter, "add_filters", r)) return r;

            for (int i = 0; i < plan.Filters.Length; i++)
            {
                FilterSnap snap;
                if (!FilterLookup.Try(world, plan.Filters[i].FilterKey, out snap, out err))
                {
                    r.Error = err;
                    r.Installed = false;
                    r.Journal = rec;
                    r.Recovery = "filters_maybe_blocking_no_exemption";
                    return r;
                }
                if (!snap.Found || !SharedVerify.FilterOurs(snap, plan.Filters[i], plan.PackageSid, out err))
                {
                    r.Error = err ?? "filter_verify_failed";
                    r.Installed = false;
                    r.Journal = rec;
                    r.Recovery = "filters_maybe_blocking_no_exemption";
                    return r;
                }
            }
            r.Installed = true;
            if (rec.State == JournalState.Planned)
            {
                rec.State = JournalState.FiltersInstalled;
                JournalIo.PreserveOwnership(prior, rec);
                if (!world.JournalWriteDurable(rec, out err))
                {
                    r.Error = err ?? "journal_write_failed";
                    r.Journal = rec;
                    r.JournalWritten = true;
                    r.Recovery = "filters_left_blocking_no_exemption";
                    return r;
                }
                r.JournalWritten = true;
            }
            r.Journal = rec;
            if (Stop(stopAfter, "write_filters_installed", r)) return r;

            if (rec.State != JournalState.Ready)
            {
                rec.State = JournalState.ExemptionPending;
                JournalIo.PreserveOwnership(prior, rec);
                if (!world.JournalWriteDurable(rec, out err))
                {
                    r.Error = err ?? "journal_write_failed";
                    r.Journal = rec;
                    r.Recovery = "filters_left_blocking_no_exemption";
                    return r;
                }
                r.JournalWritten = true;
            }
            if (Stop(stopAfter, "write_exemption_pending", r)) return r;

            ExemptionEntry[] fresh = world.ExemptionRead();
            if (fresh == null)
            {
                r.Error = "exemption_read";
                r.Journal = rec;
                r.Recovery = "filters_left_blocking_no_exemption";
                return r;
            }
            bool claims = JournalState.ClaimsExemption(rec);
            ExemptionMergeResult merge = ExemptionLogic.PlanAdd(fresh, plan.PackageSid, claims);
            if (!merge.Ok)
            {
                r.Error = merge.Error;
                r.Journal = rec;
                r.Recovery = "filters_left_blocking_no_exemption_takeover";
                return r;
            }
            if (merge.WouldSet)
            {
                if (!ExemptionLogic.SameForeignAttributesPreserved(fresh, merge.NextEntries, plan.PackageSid))
                {
                    r.Error = "exemption_attributes_lost";
                    r.Journal = rec;
                    r.Recovery = "filters_left_blocking_no_exemption";
                    return r;
                }
                if (!world.ExemptionWrite(merge.NextEntries, out err))
                {
                    r.Error = err;
                    r.ExemptionMutated = true;
                    r.Changed = true;
                    r.Journal = rec;
                    r.ExemptionWrites = 1;
                    r.Recovery = "filters_left_blocking_exemption_set_failed";
                    return r;
                }
                r.ExemptionMutated = true;
                r.Changed = true;
                r.ExemptionWrites = 1;
                ExemptionEntry[] after = world.ExemptionRead();
                if (after == null)
                {
                    r.Error = "exemption_reread";
                    r.Journal = rec;
                    r.Recovery = "filters_left_blocking_reread_failed";
                    return r;
                }
                string v = ExemptionLogic.VerifyAfterAdd(fresh, after, plan.PackageSid);
                if (v != null)
                {
                    r.Error = v;
                    r.Journal = rec;
                    r.Recovery = "filters_left_blocking_full_list_write_race";
                    return r;
                }
            }
            if (Stop(stopAfter, "add_exemption", r)) return r;

            rec.LoopbackExemptionAddedByUs = true;
            rec.State = JournalState.Ready;
            if (!world.JournalWriteDurable(rec, out err))
            {
                r.Error = err ?? "journal_ready_failed";
                r.Journal = rec;
                r.Recovery = "exemption_may_exist_filters_blocking";
                return r;
            }
            r.JournalWritten = true;
            r.Journal = rec;
            r.Ok = true;
            r.Verified = true;
            r.State = JournalState.Ready;
            r.Installed = true;
            return r;
        }

        static bool EnsureShared(IFilterWorld world, bool provider, out string error)
        {
            error = null;
            SharedObjectInfo info;
            bool found = provider ? world.ProviderGet(out info) : world.SubLayerGet(out info);
            if (found && info != null && info.Found)
            {
                return provider ? SharedVerify.ProviderOk(info, out error) : SharedVerify.SubLayerOk(info, out error);
            }
            uint st = provider ? world.ProviderAdd() : world.SubLayerAdd();
            if (st == 0)
            {
                found = provider ? world.ProviderGet(out info) : world.SubLayerGet(out info);
                if (!found || info == null || !info.Found)
                {
                    error = provider ? "provider_get_after_add" : "sublayer_get_after_add";
                    return false;
                }
                return provider ? SharedVerify.ProviderOk(info, out error) : SharedVerify.SubLayerOk(info, out error);
            }
            if (st == WfpConst.FwpEAlreadyExists)
            {
                found = provider ? world.ProviderGet(out info) : world.SubLayerGet(out info);
                if (!found || info == null || !info.Found)
                {
                    error = provider ? "provider_exists_unverified" : "sublayer_exists_unverified";
                    return false;
                }
                if (!(provider ? SharedVerify.ProviderOk(info, out error) : SharedVerify.SubLayerOk(info, out error)))
                {
                    if (error == null) error = provider ? "provider_exists_unverified" : "sublayer_exists_unverified";
                    return false;
                }
                return true;
            }
            error = (provider ? "provider_add=0x" : "sublayer_add=0x") + st.ToString("X8");
            return false;
        }

        static JournalRecord CloneJournal(JournalRecord s)
        {
            JournalRecord n = new JournalRecord();
            n.Schema = s.Schema;
            n.JournalId = s.JournalId;
            n.CreatedUtc = s.CreatedUtc;
            n.ProfileName = s.ProfileName;
            n.PackageSid = s.PackageSid;
            n.GatewayAddress = s.GatewayAddress;
            n.GatewayPort = s.GatewayPort;
            n.OwnerSid = s.OwnerSid;
            n.ProviderKey = s.ProviderKey;
            n.SubLayerKey = s.SubLayerKey;
            n.State = s.State;
            n.LoopbackExemptionAddedByUs = s.LoopbackExemptionAddedByUs;
            for (int i = 0; i < s.Filters.Count; i++)
            {
                JournalFilter f = new JournalFilter();
                f.Role = s.Filters[i].Role;
                f.FilterKey = s.Filters[i].FilterKey;
                f.FilterId = s.Filters[i].FilterId;
                f.Layer = s.Filters[i].Layer;
                f.Action = s.Filters[i].Action;
                n.Filters.Add(f);
            }
            return n;
        }

        static bool Stop(string stopAfter, string phase, MachineResult r)
        {
            if (string.IsNullOrEmpty(stopAfter)) return false;
            if (!string.Equals(stopAfter, phase, StringComparison.Ordinal)) return false;
            r.Ok = false;
            r.Error = "stopped:" + phase;
            r.State = phase;
            return true;
        }
    }

    internal static class CleanupMachine
    {
        public static MachineResult Run(IFilterWorld world, FilterPlan plan, CleanupSpec spec, string stopAfter)
        {
            MachineResult r = new MachineResult();
            r.Recovery = "leave_exact_sid_block";
            if (world == null || plan == null || spec == null)
            {
                r.Error = "machine_args";
                return r;
            }
            string g = world.GuardError();
            if (!string.IsNullOrEmpty(g))
            {
                r.Error = g;
                return r;
            }
            JournalRecord jr;
            string err;
            if (!world.JournalRead(spec.JournalId, out jr, out err) || jr == null)
            {
                r.Error = err ?? "journal_missing";
                r.Installed = true;
                return r;
            }
            r.Journal = jr;
            r.Installed = true;
            if (!JournalIo.MatchesPlan(jr, plan, out err))
            {
                r.Error = err;
                return r;
            }
            if (!string.Equals(jr.JournalId, spec.JournalId, StringComparison.Ordinal)
                || !string.Equals(jr.ProfileName, spec.ProfileName, StringComparison.Ordinal))
            {
                r.Error = "journal_identity_mismatch";
                return r;
            }
            if (Stop(stopAfter, "load_journal", r)) return r;

            JobScanStats stats;
            IHeldJobProof held = world as IHeldJobProof;
            bool proofOk;
            if (held != null)
            {
                proofOk = held.TryHeldTreeProof(out err, out stats) && JobProofEval.EvaluateHeld(stats, out err);
            }
            else
            {
                proofOk = world.ProveJobEmpty(spec.JobName, jr.PackageSid, out err, out stats) && JobProofEval.Evaluate(stats, out err);
            }
            if (!proofOk)
            {
                r.Error = err ?? "job_not_proven_empty";
                return r;
            }
            if (Stop(stopAfter, "job_proof", r)) return r;

            ExemptionEntry[] before = world.ExemptionRead();
            if (before == null)
            {
                r.Error = "exemption_read";
                r.DeletedFilters = false;
                return r;
            }
            bool weOwn = JournalState.ClaimsExemption(jr);
            ExemptionMergeResult merge = ExemptionLogic.PlanRemove(before, jr.PackageSid, weOwn);
            if (!merge.Ok)
            {
                r.Error = merge.Error;
                r.DeletedFilters = false;
                return r;
            }
            if (merge.WouldSet)
            {
                if (!world.ExemptionWrite(merge.NextEntries, out err))
                {
                    r.Error = err;
                    r.ExemptionMutated = true;
                    r.Changed = true;
                    r.ExemptionWrites = 1;
                    r.DeletedFilters = false;
                    return r;
                }
                r.ExemptionMutated = true;
                r.Changed = true;
                r.ExemptionWrites = 1;
                ExemptionEntry[] after = world.ExemptionRead();
                if (after == null)
                {
                    r.Error = "exemption_reread";
                    r.DeletedFilters = false;
                    return r;
                }
                string v = ExemptionLogic.VerifyAfterRemove(before, after, jr.PackageSid);
                if (v != null)
                {
                    r.Error = v;
                    r.DeletedFilters = false;
                    return r;
                }
            }
            ExemptionEntry[] now = world.ExemptionRead();
            if (now == null)
            {
                r.Error = "exemption_reread";
                r.DeletedFilters = false;
                return r;
            }
            if (ExemptionLogic.Contains(now, jr.PackageSid))
            {
                r.Error = "exemption_still_present";
                r.DeletedFilters = false;
                return r;
            }
            if (Stop(stopAfter, "exemption_absent", r)) return r;

            for (int i = 0; i < jr.Filters.Count; i++)
            {
                Guid key;
                try { key = new Guid(jr.Filters[i].FilterKey); }
                catch
                {
                    r.Error = "bad_journal_filter_key";
                    return r;
                }
                PlannedFilter pf = null;
                for (int p = 0; p < plan.Filters.Length; p++)
                {
                    if (plan.Filters[p].FilterKey == key) pf = plan.Filters[p];
                }
                if (pf == null)
                {
                    r.Error = "journal_filter_not_in_plan";
                    return r;
                }
                FilterSnap snap;
                if (!FilterLookup.Try(world, key, out snap, out err))
                {
                    r.Error = err;
                    r.DeletedFilters = false;
                    r.Verified = false;
                    return r;
                }
                if (snap.Found)
                {
                    if (!SharedVerify.FilterOurs(snap, pf, jr.PackageSid, out err))
                    {
                        r.Error = "delete_identity_mismatch:" + err;
                        return r;
                    }
                    uint st = world.FilterDelete(key);
                    if (st != 0 && st != WfpConst.FwpENotFound)
                    {
                        r.Error = "filter_delete=0x" + st.ToString("X8");
                        r.DeletedFilters = true;
                        r.FiltersMutated = true;
                        r.Changed = true;
                        return r;
                    }
                    r.DeletedFilters = true;
                    r.FiltersMutated = true;
                    r.Changed = true;
                }
                FilterSnap gone;
                if (!FilterLookup.Try(world, key, out gone, out err))
                {
                    r.Error = "filter_absent_unverified:" + err;
                    r.Verified = false;
                    return r;
                }
                if (gone.Found)
                {
                    r.Error = "filter_still_present";
                    r.Verified = false;
                    return r;
                }
            }
            if (Stop(stopAfter, "filters_absent", r)) return r;

            if (!world.JournalDelete(spec.JournalId, out err))
            {
                r.Ok = false;
                r.Error = err ?? "journal_delete_failed";
                r.Verified = false;
                r.Installed = false;
                r.State = "filters_removed_journal_remains";
                r.Recovery = "exemption_and_filters_gone_journal_left";
                return r;
            }
            r.JournalDeleted = true;
            if (world.JournalExists(spec.JournalId))
            {
                r.Ok = false;
                r.Error = "journal_still_present";
                r.Verified = false;
                return r;
            }
            r.Ok = true;
            r.Verified = true;
            r.Installed = false;
            r.State = "removed";
            r.Journal = null;
            r.Recovery = null;
            return r;
        }

        static bool Stop(string stopAfter, string phase, MachineResult r)
        {
            if (string.IsNullOrEmpty(stopAfter)) return false;
            if (!string.Equals(stopAfter, phase, StringComparison.Ordinal)) return false;
            r.Ok = false;
            r.Error = "stopped:" + phase;
            r.State = phase;
            return true;
        }
    }

    internal class FakeWorld : IFilterWorld
    {
        public string Guard;
        public bool FailJournalWrite;
        public string ConcurrentRevokeSid;
        public string ConcurrentAttrSid;
        public uint ConcurrentAttrValue;
        public string JournalReadError;
        public bool ThrowOnFilterAdd;
        public Guid FilterGetFailKey;
        public int FilterGetFailCount;
        public int FilterGetFailSkip;
        public uint ProviderAddResult;
        public uint SubLayerAddResult;
        public JobScanStats JobStats;
        public string JobError;
        public int ExemptionWriteCount;
        public int FilterAddCount;
        public int FilterDeleteCount;

        JournalRecord journal;
        SharedObjectInfo provider;
        SharedObjectInfo sublayer;
        readonly Dictionary<Guid, FilterSnap> filters = new Dictionary<Guid, FilterSnap>();
        readonly List<ExemptionEntry> exemptions = new List<ExemptionEntry>();
        string lastOwner = WfpConst.SidAdministrators;

        public FakeWorld()
        {
            JobStats = JobScanStats.TrustedEmpty();
            ProviderAddResult = 0;
            SubLayerAddResult = 0;
        }

        public void PlantExemption(string sid, uint attrs)
        {
            if (ExemptionLogic.Contains(exemptions, sid)) return;
            exemptions.Add(new ExemptionEntry(sid, attrs));
        }

        public void PlantFilter(FilterSnap snap)
        {
            filters[snap.FilterKey] = snap;
        }

        public void PlantProvider(string owner, uint flags, bool securityKnown)
        {
            provider = new SharedObjectInfo();
            provider.Found = true;
            provider.Flags = flags;
            provider.OwnerSid = owner;
            provider.SecurityKnown = securityKnown;
        }

        public void PlantSubLayer(string owner, uint flags, ushort weight, Guid prov, bool securityKnown)
        {
            sublayer = new SharedObjectInfo();
            sublayer.Found = true;
            sublayer.Flags = flags;
            sublayer.Weight = weight;
            sublayer.ProviderKey = prov;
            sublayer.OwnerSid = owner;
            sublayer.SecurityKnown = securityKnown;
        }

        public ExemptionEntry[] ExemptionSnapshot()
        {
            return ExemptionLogic.Copy(exemptions);
        }

        public string GuardError()
        {
            return Guard;
        }

        public bool JournalRead(string journalId, out JournalRecord rec, out string error)
        {
            rec = null;
            if (!string.IsNullOrEmpty(JournalReadError))
            {
                error = JournalReadError;
                return false;
            }
            error = null;
            if (journal == null || !string.Equals(journal.JournalId, journalId, StringComparison.Ordinal))
            {
                error = "journal_missing";
                return false;
            }
            rec = ApplyMachineClone(journal);
            return true;
        }

        public bool JournalWriteDurable(JournalRecord rec, out string error)
        {
            error = null;
            if (FailJournalWrite)
            {
                error = "journal_write_failed";
                return false;
            }
            journal = ApplyMachineClone(rec);
            return true;
        }

        public bool JournalDelete(string journalId, out string error)
        {
            error = null;
            if (journal == null)
            {
                return true;
            }
            if (!string.Equals(journal.JournalId, journalId, StringComparison.Ordinal))
            {
                error = "journal_id_mismatch";
                return false;
            }
            journal = null;
            return true;
        }

        public bool JournalExists(string journalId)
        {
            return journal != null && string.Equals(journal.JournalId, journalId, StringComparison.Ordinal);
        }

        public bool ProviderGet(out SharedObjectInfo info)
        {
            info = provider;
            return provider != null && provider.Found;
        }

        public uint ProviderAdd()
        {
            if (ProviderAddResult != 0) return ProviderAddResult;
            if (provider != null && provider.Found) return WfpConst.FwpEAlreadyExists;
            provider = new SharedObjectInfo();
            provider.Found = true;
            provider.Flags = WfpConst.FwpmProviderFlagPersistent;
            provider.OwnerSid = lastOwner;
            provider.SecurityKnown = true;
            return 0;
        }

        public bool SubLayerGet(out SharedObjectInfo info)
        {
            info = sublayer;
            return sublayer != null && sublayer.Found;
        }

        public uint SubLayerAdd()
        {
            if (SubLayerAddResult != 0) return SubLayerAddResult;
            if (sublayer != null && sublayer.Found) return WfpConst.FwpEAlreadyExists;
            sublayer = new SharedObjectInfo();
            sublayer.Found = true;
            sublayer.Flags = WfpConst.FwpmSubLayerFlagPersistent;
            sublayer.Weight = WfpConst.SubLayerWeight;
            sublayer.ProviderKey = WfpGuids.Provider;
            sublayer.OwnerSid = lastOwner;
            sublayer.SecurityKnown = true;
            return 0;
        }

        public bool FilterGet(Guid key, out FilterSnap snap)
        {
            snap = new FilterSnap();
            if (FilterGetFailCount > 0 && key == FilterGetFailKey)
            {
                if (FilterGetFailSkip > 0)
                {
                    FilterGetFailSkip--;
                }
                else
                {
                    FilterGetFailCount--;
                    snap.QueryOk = false;
                    snap.QueryError = "injected_filter_get_fail";
                    snap.Found = false;
                    return false;
                }
            }
            FilterSnap stored;
            if (filters.TryGetValue(key, out stored) && stored != null)
            {
                snap = stored;
                snap.QueryOk = true;
                snap.Found = true;
                return true;
            }
            snap.QueryOk = true;
            snap.Found = false;
            return true;
        }

        public uint FilterAdd(PlannedFilter planned, out ulong id)
        {
            id = 0;
            FilterAddCount++;
            if (ThrowOnFilterAdd)
            {
                throw new InvalidOperationException("injected_filter_add");
            }
            FilterSnap existing;
            if (filters.TryGetValue(planned.FilterKey, out existing) && existing != null && existing.Found)
            {
                return WfpConst.FwpEAlreadyExists;
            }
            FilterSnap s = new FilterSnap();
            s.QueryOk = true;
            s.Found = true;
            s.FilterKey = planned.FilterKey;
            s.LayerKey = planned.LayerKey;
            s.SubLayerKey = WfpGuids.SubLayer;
            s.ProviderKey = WfpGuids.Provider;
            s.Flags = WfpConst.FwpmFilterFlagPersistent;
            s.ActionType = planned.ActionType;
            s.Weight = planned.Weight;
            s.WeightType = planned.WeightType != 0 ? planned.WeightType : WfpConst.FwpUint8;
            if (planned.Expected != null)
            {
                s.Conditions = new ConditionSpec[planned.Expected.Length];
                for (int i = 0; i < planned.Expected.Length; i++)
                {
                    ConditionSpec e = planned.Expected[i];
                    ConditionSpec c = new ConditionSpec();
                    c.FieldKey = e.FieldKey;
                    c.MatchType = e.MatchType;
                    c.ValueType = e.ValueType;
                    c.Sid = e.Sid;
                    c.U32 = e.U32;
                    c.U16 = e.U16;
                    c.U8 = e.U8;
                    s.Conditions[i] = c;
                    if (c.FieldKey == WfpGuids.CondAlePackageId) s.PackageSid = c.Sid;
                }
            }
            filters[planned.FilterKey] = s;
            id = (ulong)(1000 + FilterAddCount);
            return 0;
        }

        public uint FilterDelete(Guid key)
        {
            FilterDeleteCount++;
            if (!filters.ContainsKey(key)) return WfpConst.FwpENotFound;
            filters.Remove(key);
            return 0;
        }

        public ExemptionEntry[] ExemptionRead()
        {
            return ExemptionLogic.Copy(exemptions);
        }

        public bool ExemptionWrite(ExemptionEntry[] entries, out string error)
        {
            error = null;
            ExemptionWriteCount++;
            exemptions.Clear();
            ExemptionEntry[] copy = ExemptionLogic.Copy(entries);
            for (int i = 0; i < copy.Length; i++) exemptions.Add(copy[i]);
            if (!string.IsNullOrEmpty(ConcurrentRevokeSid))
            {
                int idx = ExemptionLogic.Find(exemptions, ConcurrentRevokeSid);
                if (idx >= 0) exemptions.RemoveAt(idx);
            }
            if (!string.IsNullOrEmpty(ConcurrentAttrSid))
            {
                int idx = ExemptionLogic.Find(exemptions, ConcurrentAttrSid);
                if (idx >= 0) exemptions[idx].Attributes = ConcurrentAttrValue;
            }
            return true;
        }

        public bool ProveJobEmpty(string jobName, string packageSid, out string error, out JobScanStats stats)
        {
            stats = JobStats;
            error = JobError;
            if (!string.IsNullOrEmpty(JobError)) return false;
            return JobProofEval.Evaluate(JobStats, out error);
        }

        static JournalRecord ApplyMachineClone(JournalRecord s)
        {
            if (s == null) return null;
            JournalRecord n = new JournalRecord();
            n.Schema = s.Schema;
            n.JournalId = s.JournalId;
            n.CreatedUtc = s.CreatedUtc;
            n.ProfileName = s.ProfileName;
            n.PackageSid = s.PackageSid;
            n.GatewayAddress = s.GatewayAddress;
            n.GatewayPort = s.GatewayPort;
            n.OwnerSid = s.OwnerSid;
            n.ProviderKey = s.ProviderKey;
            n.SubLayerKey = s.SubLayerKey;
            n.State = s.State;
            n.LoopbackExemptionAddedByUs = s.LoopbackExemptionAddedByUs;
            for (int i = 0; i < s.Filters.Count; i++)
            {
                JournalFilter f = new JournalFilter();
                f.Role = s.Filters[i].Role;
                f.FilterKey = s.Filters[i].FilterKey;
                f.FilterId = s.Filters[i].FilterId;
                f.Layer = s.Filters[i].Layer;
                f.Action = s.Filters[i].Action;
                n.Filters.Add(f);
            }
            return n;
        }
    }

    internal sealed class FakeHeldWorld : FakeWorld, IHeldJobProof
    {
        public JobScanStats HeldStats;

        public bool TryHeldTreeProof(out string error, out JobScanStats stats)
        {
            error = null;
            stats = HeldStats != null ? HeldStats : JobScanStats.TrustedEmpty();
            return true;
        }
    }
}
