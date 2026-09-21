using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Nmzp.NativeEgressFilter
{
    internal static class SelfTest
    {
        static int fails;
        static readonly List<string> names = new List<string>();

        public static int Run()
        {
            fails = 0;
            names.Clear();
            Native.ResetMutationCounters();

            Check("x64", IntPtr.Size == 8);
            string layoutErr;
            Check("layout", Native.LayoutOk(out layoutErr));
            if (layoutErr != null) Note(layoutErr);

            Check("size_value", Marshal.SizeOf(typeof(FwpValue0)) == 16);
            Check("size_blob", Marshal.SizeOf(typeof(FwpByteBlob)) == 16);
            Check("size_action", Marshal.SizeOf(typeof(FwpmAction0)) == 20);
            Check("size_cond", Marshal.SizeOf(typeof(FwpmFilterCondition0)) == 40);
            Check("size_filter", Marshal.SizeOf(typeof(FwpmFilter0)) == 200);
            Check("size_provider", Marshal.SizeOf(typeof(FwpmProvider0)) == 64);
            Check("size_sublayer", Marshal.SizeOf(typeof(FwpmSubLayer0)) == 72);
            Check("size_session", Marshal.SizeOf(typeof(FwpmSession0)) == 72);
            Check("size_sidattr", Marshal.SizeOf(typeof(SidAndAttributes)) == 16);

            Check("guid_v4", WfpGuids.LayerAleAuthConnectV4.ToString("D") == "c38d57d1-05a7-4c33-904f-7fbceee60e82");
            Check("guid_v6", WfpGuids.LayerAleAuthConnectV6.ToString("D") == "4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
            Check("guid_pkg", WfpGuids.CondAlePackageId.ToString("D") == "71bc78fa-f17c-4997-a602-6abb261f351c");
            Check("guid_addr", WfpGuids.CondIpRemoteAddress.ToString("D") == "b235ae9a-1d64-49b8-a44c-5ff3d9095045");
            Check("guid_proto", WfpGuids.CondIpProtocol.ToString("D") == "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
            Check("guid_port", WfpGuids.CondIpRemotePort.ToString("D") == "c35a604d-d22b-4e1a-91b4-68f674ee674b");
            Check("action_block", WfpConst.FwpActionBlock == 0x00001001);
            Check("action_permit", WfpConst.FwpActionPermit == 0x00001002);
            Check("flag_clear_right", WfpConst.FwpmFilterFlagClearActionRight == 8);
            Check("tcp", WfpConst.IpProtoTcp == 6);
            Check("loopback_host_order", WfpConst.Ipv4LoopbackHostOrder == 0x7F000001);
            Check("session_dynamic_flag", WfpConst.FwpmSessionFlagDynamic == 1);

            SpecTests();
            PlanTests();
            ExemptionTests();
            JournalTests();
            JobNameTests();
            DeriveTests();
            JobEvalTests();
            MachineTests();
            LeaseTests();
            NonAdminTests();

            Check("no_mutations_during_selftest", Native.MutationSum() == 0);
            Check("no_exemption_set", Native.ExemptionSetCalls == 0);
            Check("no_exemption_get", Native.ExemptionGetCalls == 0);
            Check("no_filter_add", Native.FwpmFilterAddCalls == 0);

            bool elevated = Native.IsElevatedAdmin();
            if (elevated)
            {
                Note("elevated_selftest_did_not_call_real_apply");
            }

            Console.WriteLine(ResultJson.Emit(
                fails == 0,
                "selftest",
                false,
                false,
                false,
                fails == 0 ? null : "failed=" + fails.ToString(CultureInfo.InvariantCulture),
                null,
                null,
                Extra()));
            return fails == 0 ? 0 : 7;
        }

        static Dictionary<string, string> Extra()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.Ordinal);
            d["failCount"] = fails.ToString(CultureInfo.InvariantCulture);
            d["caseCount"] = names.Count.ToString(CultureInfo.InvariantCulture);
            d["elevated"] = Native.IsElevatedAdmin() ? "true" : "false";
            d["mutationSum"] = Native.MutationSum().ToString(CultureInfo.InvariantCulture);
            return d;
        }

        static void SpecTests()
        {
            ExpectOkSpec("{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":49152}");
            ExpectBadSpec("unknown_field", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1,\"allowIPs\":[]}");
            ExpectBadSpec("sid_field", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1,\"packageSid\":\"S-1-5-18\"}");
            ExpectBadSpec("script_field", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1,\"script\":\"calc.exe\"}");
            ExpectBadSpec("bad_prefix", "{\"profileName\":\"nmzp.nisol.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1}");
            ExpectBadSpec("short_nonce", "{\"profileName\":\"nmzp.agent.abc\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1}");
            ExpectBadSpec("path_chars", "{\"profileName\":\"nmzp.agent.abc12345/x\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1}");
            ExpectBadSpec("localhost", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"localhost\",\"gatewayPort\":1}");
            ExpectBadSpec("v6", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"::1\",\"gatewayPort\":1}");
            ExpectBadSpec("other_loopback", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.2\",\"gatewayPort\":1}");
            ExpectBadSpec("port0", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":0}");
            ExpectBadSpec("port65536", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":65536}");
            ExpectBadSpec("port_float", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1.5}");
            ExpectBadSpec("dup_key", "{\"profileName\":\"nmzp.agent.abc12345\",\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1}");
            ExpectBadSpec("trailing_comma", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1,}");
            ExpectBadSpec("comment", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":1 /*x*/}");
            ExpectBadSpec("missing_port", "{\"profileName\":\"nmzp.agent.abc12345\",\"gatewayAddress\":\"127.0.0.1\"}");
            string big = new string('a', Json.MaxSpecBytes + 8);
            try
            {
                SpecParser.ParseFilterSpec("{\"profileName\":\"" + big + "\"}");
                Fail("oversize");
            }
            catch (JsonException)
            {
                Pass("oversize");
            }
        }

        static void PlanTests()
        {
            FilterSpec spec = SpecParser.ParseFilterSpec("{\"profileName\":\"nmzp.agent.deadbeef01\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":55555}");
            FilterPlan a = Planner.Build(spec, "S-1-15-2-1-2-3-4-5-6-7");
            FilterPlan b = Planner.Build(spec, "S-1-15-2-1-2-3-4-5-6-7");
            Check("plan_filter_count", a.Filters.Length == 3);
            Check("plan_roles", a.Filters[0].Role == "v4_allow_tcp_gateway" && a.Filters[1].Role == "v4_block_rest" && a.Filters[2].Role == "v6_block_all");
            Check("plan_allow_weight", a.Filters[0].Weight == 15 && a.Filters[0].Action == "permit");
            Check("plan_block_weight", a.Filters[1].Weight == 1 && a.Filters[1].Action == "block");
            Check("plan_v6_block", a.Filters[2].Layer == "ALE_AUTH_CONNECT_V6" && a.Filters[2].Action == "block");
            Check("plan_no_hard_permit", !a.Filters[0].ClearActionRight && !a.Filters[1].ClearActionRight && !a.Filters[2].ClearActionRight);
            Check("plan_persistent", a.Filters[0].Persistent && a.Filters[1].Persistent && a.Filters[2].Persistent);
            Check("plan_allow_conds", a.Filters[0].Conditions.Length == 4);
            Check("plan_allow_tcp", Join(a.Filters[0].Conditions).IndexOf("IP_PROTOCOL==TCP", StringComparison.Ordinal) >= 0);
            Check("plan_allow_addr", Join(a.Filters[0].Conditions).IndexOf("IP_REMOTE_ADDRESS==127.0.0.1", StringComparison.Ordinal) >= 0);
            Check("plan_allow_port", Join(a.Filters[0].Conditions).IndexOf("IP_REMOTE_PORT==55555", StringComparison.Ordinal) >= 0);
            Check("plan_block_only_sid", a.Filters[1].Conditions.Length == 1 && a.Filters[2].Conditions.Length == 1);
            Check("plan_deterministic", a.Filters[0].FilterKey == b.Filters[0].FilterKey && a.JournalId == b.JournalId);
            Check("plan_keys_distinct", a.Filters[0].FilterKey != a.Filters[1].FilterKey && a.Filters[1].FilterKey != a.Filters[2].FilterKey);
            Check("plan_own_provider", a.ProviderKey == WfpGuids.Provider && a.SubLayerKey == WfpGuids.SubLayer);
            Check("plan_job_contract", a.JobNameLocal == "Local\\nmzp.agent.deadbeef01.job");
            string json = Planner.ToRedactedJson(a, "plan", true, null);
            Check("plan_json_verified_false", json.IndexOf("\"verified\":false", StringComparison.Ordinal) >= 0);
            Check("plan_json_no_dump", json.IndexOf("exemptionList", StringComparison.Ordinal) < 0);
            FilterSpec spec2 = SpecParser.ParseFilterSpec("{\"profileName\":\"nmzp.agent.deadbeef02\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":55555}");
            FilterPlan c = Planner.Build(spec2, "S-1-15-2-1-2-3-4-5-6-8");
            Check("plan_keys_per_profile", a.Filters[0].FilterKey != c.Filters[0].FilterKey);
            Check("plan_allow_expected", a.Filters[0].Expected != null && a.Filters[0].Expected.Length == 4);
            Check("plan_block_expected", a.Filters[1].Expected != null && a.Filters[1].Expected.Length == 1 && a.Filters[2].Expected.Length == 1);
            FilterOursTests(a);
            ParseConditionsTests();
            TokenGroupsTests();
        }

        static FilterSnap SnapFromPlanned(PlannedFilter p)
        {
            FilterSnap s = new FilterSnap();
            s.QueryOk = true;
            s.Found = true;
            s.FilterKey = p.FilterKey;
            s.LayerKey = p.LayerKey;
            s.SubLayerKey = WfpGuids.SubLayer;
            s.ProviderKey = WfpGuids.Provider;
            s.Flags = WfpConst.FwpmFilterFlagPersistent;
            s.ActionType = p.ActionType;
            s.Weight = p.Weight;
            s.WeightType = p.WeightType;
            if (p.Expected != null)
            {
                s.Conditions = new ConditionSpec[p.Expected.Length];
                for (int i = 0; i < p.Expected.Length; i++)
                {
                    ConditionSpec e = p.Expected[i];
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
            return s;
        }

        static void FilterOursTests(FilterPlan a)
        {
            string err;
            FilterSnap ok = SnapFromPlanned(a.Filters[0]);
            Check("ours_ok", SharedVerify.FilterOurs(ok, a.Filters[0], a.PackageSid, out err));
            FilterSnap w = SnapFromPlanned(a.Filters[0]);
            w.Weight = 1;
            Check("ours_weight", !SharedVerify.FilterOurs(w, a.Filters[0], a.PackageSid, out err) && err == "filter_weight");
            FilterSnap wt = SnapFromPlanned(a.Filters[0]);
            wt.WeightType = WfpConst.FwpUint64;
            Check("ours_weight_type", !SharedVerify.FilterOurs(wt, a.Filters[0], a.PackageSid, out err) && err == "filter_weight_type");
            FilterSnap port = SnapFromPlanned(a.Filters[0]);
            port.Conditions[3].U16 = 1;
            Check("ours_wrong_port", !SharedVerify.FilterOurs(port, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_mismatch");
            FilterSnap proto = SnapFromPlanned(a.Filters[0]);
            proto.Conditions[1].U8 = 17;
            Check("ours_wrong_protocol", !SharedVerify.FilterOurs(proto, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_mismatch");
            FilterSnap addr = SnapFromPlanned(a.Filters[0]);
            addr.Conditions[2].U32 = 0x7F000002;
            Check("ours_wrong_addr", !SharedVerify.FilterOurs(addr, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_mismatch");
            FilterSnap extra = SnapFromPlanned(a.Filters[0]);
            ConditionSpec[] grow = new ConditionSpec[5];
            for (int i = 0; i < 4; i++) grow[i] = extra.Conditions[i];
            grow[4] = ConditionSpec.U8Eq(WfpGuids.CondIpProtocol, 1);
            extra.Conditions = grow;
            Check("ours_extra_cond", !SharedVerify.FilterOurs(extra, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_count");
            FilterSnap miss = SnapFromPlanned(a.Filters[0]);
            miss.Conditions = new ConditionSpec[] { miss.Conditions[0], miss.Conditions[1], miss.Conditions[2] };
            Check("ours_missing_cond", !SharedVerify.FilterOurs(miss, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_count");
            FilterSnap unk = SnapFromPlanned(a.Filters[0]);
            unk.Conditions[1].ValueType = 99;
            Check("ours_unknown_type", !SharedVerify.FilterOurs(unk, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_unknown_type");
            FilterSnap field = SnapFromPlanned(a.Filters[0]);
            field.Conditions[1].FieldKey = Guid.NewGuid();
            Check("ours_unknown_field", !SharedVerify.FilterOurs(field, a.Filters[0], a.PackageSid, out err) && err == "filter_condition_unknown_field");
            FilterSnap mt = SnapFromPlanned(a.Filters[0]);
            mt.Conditions[0].MatchType = 1;
            Check("ours_match_type", !SharedVerify.FilterOurs(mt, a.Filters[0], a.PackageSid, out err) && err == "filter_match_type");
        }

        static void ParseConditionsTests()
        {
            FwpmFilter0 f = new FwpmFilter0();
            FilterSnap snap = new FilterSnap();
            snap.QueryOk = true;
            f.numFilterConditions = 0;
            f.filterCondition = IntPtr.Zero;
            RealFilterWorld.ParseConditions(f, snap);
            Check("parse_cond_zero_ok", snap.QueryOk && snap.Conditions != null && snap.Conditions.Length == 0);

            snap = new FilterSnap();
            snap.QueryOk = true;
            f.numFilterConditions = (uint)(WfpConst.MaxFilterConditions + 1);
            f.filterCondition = new IntPtr(8);
            RealFilterWorld.ParseConditions(f, snap);
            Check("parse_cond_cap", !snap.QueryOk && snap.QueryError == "filter_condition_malformed");

            snap = new FilterSnap();
            snap.QueryOk = true;
            f.numFilterConditions = 1;
            f.filterCondition = IntPtr.Zero;
            RealFilterWorld.ParseConditions(f, snap);
            Check("parse_cond_null_ptr", !snap.QueryOk && snap.QueryError == "filter_condition_malformed");
        }

        static void TokenGroupsTests()
        {
            string err;
            IntPtr admin = IntPtr.Zero;
            Check("groups_layout_null", !OwnedNetworkJobLease.ParseTokenGroupsAdminEnabled(IntPtr.Zero, 32, new IntPtr(1), out err) && err == "lease_groups_layout");
            if (!Native.ConvertStringSidToSid(WfpConst.SidAdministrators, out admin) || admin == IntPtr.Zero)
            {
                Fail("groups_admin_sid");
                return;
            }
            try
            {
                IntPtr tiny = Marshal.AllocHGlobal(8);
                try
                {
                    Marshal.WriteInt32(tiny, 0, 10000);
                    Marshal.WriteInt32(tiny, 4, 0);
                    Check("groups_count", !OwnedNetworkJobLease.ParseTokenGroupsAdminEnabled(tiny, 8, admin, out err) && err == "lease_groups_count");
                    Marshal.WriteInt32(tiny, 0, 4);
                    Check("groups_overflow", !OwnedNetworkJobLease.ParseTokenGroupsAdminEnabled(tiny, 8, admin, out err) && err == "lease_groups_overflow");
                    Marshal.WriteInt32(tiny, 0, 0);
                    Check("groups_empty_ok", OwnedNetworkJobLease.ParseTokenGroupsAdminEnabled(tiny, 8, admin, out err));
                }
                finally
                {
                    Marshal.FreeHGlobal(tiny);
                }
                int stride = Marshal.SizeOf(typeof(SidAndAttributes));
                int bytes = 8 + stride;
                IntPtr wild = Marshal.AllocHGlobal(bytes);
                try
                {
                    for (int i = 0; i < bytes; i++) Marshal.WriteByte(wild, i, 0);
                    Marshal.WriteInt32(wild, 0, 1);
                    Marshal.WriteIntPtr(wild, 8, new IntPtr(1));
                    Check("groups_sid_range", !OwnedNetworkJobLease.ParseTokenGroupsAdminEnabled(wild, bytes, admin, out err) && err == "lease_groups_sid_range");
                }
                finally
                {
                    Marshal.FreeHGlobal(wild);
                }
            }
            finally
            {
                Native.LocalFree(admin);
            }
        }

        static void ExemptionTests()
        {
            string ours = "S-1-15-2-9";
            string other = "S-1-15-2-8";
            ExemptionEntry[] baseList = new ExemptionEntry[] { new ExemptionEntry(other, 7) };
            ExemptionMergeResult add = ExemptionLogic.PlanAdd(baseList, ours, false);
            Check("ex_add_ok", add.Ok && add.WouldSet && add.AddedOurs && add.NextEntries.Length == 2);
            Check("ex_add_preserve_attr", ExemptionLogic.SameForeignAttributesPreserved(baseList, add.NextEntries, ours)
                && add.NextEntries[ExemptionLogic.Find(add.NextEntries, other)].Attributes == 7);
            ExemptionMergeResult take = ExemptionLogic.PlanAdd(new ExemptionEntry[] { new ExemptionEntry(other, 0), new ExemptionEntry(ours, 0) }, ours, false);
            Check("ex_takeover", !take.Ok && take.TakeoverRefused);
            ExemptionMergeResult idem = ExemptionLogic.PlanAdd(new ExemptionEntry[] { new ExemptionEntry(other, 0), new ExemptionEntry(ours, 0) }, ours, true);
            Check("ex_idempotent", idem.Ok && !idem.WouldSet);
            ExemptionMergeResult rm = ExemptionLogic.PlanRemove(new ExemptionEntry[] { new ExemptionEntry(other, 7), new ExemptionEntry(ours, 0) }, ours, true);
            Check("ex_remove_only_ours", rm.Ok && rm.WouldSet && rm.NextEntries.Length == 1 && rm.NextEntries[0].Sid == other && rm.NextEntries[0].Attributes == 7);
            ExemptionMergeResult rmNo = ExemptionLogic.PlanRemove(new ExemptionEntry[] { new ExemptionEntry(other, 0), new ExemptionEntry(ours, 0) }, ours, false);
            Check("ex_remove_unknown_blocks_filters", !rmNo.Ok && rmNo.BlockFilterDelete && rmNo.Error == "exemption_conflict_leave_block");
            Check("ex_verify_add", ExemptionLogic.VerifyAfterAdd(baseList, add.NextEntries, ours) == null);
            Check("ex_verify_drop", ExemptionLogic.VerifyAfterAdd(baseList, new ExemptionEntry[] { new ExemptionEntry(ours, 0) }, ours) == "exemption_concurrent_change");
            Check("ex_verify_missing", ExemptionLogic.VerifyAfterAdd(baseList, baseList, ours) == "reread_missing_ours");
            Check("ex_verify_rm", ExemptionLogic.VerifyAfterRemove(new ExemptionEntry[] { new ExemptionEntry(other, 7), new ExemptionEntry(ours, 0) }, new ExemptionEntry[] { new ExemptionEntry(other, 7) }, ours) == null);
            Check("ex_extra_ok", ExemptionLogic.VerifyAfterAdd(baseList, new ExemptionEntry[] { new ExemptionEntry(other, 7), new ExemptionEntry(ours, 0), new ExemptionEntry("S-1-15-2-7", 1) }, ours) == null);
            Check("ex_attr_changed", ExemptionLogic.VerifyAfterAdd(baseList, new ExemptionEntry[] { new ExemptionEntry(other, 9), new ExemptionEntry(ours, 0) }, ours) == "exemption_concurrent_change");
            Check("ex_same_entries", ExemptionLogic.SameEntries(baseList, new ExemptionEntry[] { new ExemptionEntry(other, 7) }));
            Check("ex_same_entries_attr", !ExemptionLogic.SameEntries(baseList, new ExemptionEntry[] { new ExemptionEntry(other, 8) }));
        }

        static void JournalTests()
        {
            FilterSpec spec = SpecParser.ParseFilterSpec("{\"profileName\":\"nmzp.agent.cafe1234\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":9}");
            FilterPlan plan = Planner.Build(spec, "S-1-15-2-1-2-3-4-5-6-7");
            JournalRecord rec = JournalIo.FromPlan(plan, "S-1-5-32-544", "filters_installed");
            string json = JournalIo.Serialize(rec);
            JournalRecord back = JournalIo.ParseLoose(json);
            Check("jr_roundtrip_id", back.JournalId == rec.JournalId && back.Filters.Count == 3);
            Check("jr_not_added_yet", back.LoopbackExemptionAddedByUs == false);
            string dir = Path.Combine(Path.GetTempPath(), "nmzp-egress-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string path = Names.JournalPath(dir, rec.JournalId);
                string werr;
                Check("jr_durable", JournalIo.DurableWrite(path, json, out werr));
                JournalRecord r2;
                string err;
                Check("jr_read_temp", JournalIo.TryRead(path, out r2, out err) && r2.ProfileName == rec.ProfileName);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        static void JobNameTests()
        {
            string p = "nmzp.agent.abcdef01";
            Check("job_local", Names.JobNameOk("Local\\nmzp.agent.abcdef01.job", p));
            Check("job_global", Names.JobNameOk("Global\\nmzp.agent.abcdef01.job", p));
            Check("job_wrong_nonce", !Names.JobNameOk("Local\\nmzp.agent.zzzzzzzz.job", p));
            Check("job_prefix_batch", !Names.JobNameOk("Local\\nmzp.agent.", p));
            Check("job_nt", !Names.JobNameOk("\\??\\C:\\x", p));
            Check("job_extra_slash", !Names.JobNameOk("Local\\nmzp.agent.abcdef01\\job", p));
            try
            {
                SpecParser.ParseCleanupSpec("{\"profileName\":\"nmzp.agent.abcdef01\",\"journalId\":\"11111111-1111-1111-1111-111111111111\",\"jobEmptyProof\":{\"kind\":\"boolean\",\"jobName\":\"Local\\\\nmzp.agent.abcdef01.job\"}}");
                Fail("cleanup_kind");
            }
            catch (JsonException)
            {
                Pass("cleanup_kind");
            }
        }

        static void JobEvalTests()
        {
            Check("enum_full_eq", JobProofEval.EnumBufferFull(64, 64));
            Check("enum_full_gt", JobProofEval.EnumBufferFull(68, 64));
            Check("enum_not_full", !JobProofEval.EnumBufferFull(60, 64));
            JobScanStats ok = JobScanStats.TrustedEmpty();
            string err;
            Check("job_eval_empty", JobProofEval.Evaluate(ok, out err));
            ok.SystemDenied = 4;
            Check("job_eval_system_denied_ok", !JobProofEval.Evaluate(ok, out err) && err == "sid_scan_inconclusive");
            JobScanStats miss = JobScanStats.TrustedEmpty();
            miss.JobMissing = true;
            Check("job_missing_not_empty", !JobProofEval.Evaluate(miss, out err) && err == "job_open_failed");
            JobScanStats live = JobScanStats.TrustedEmpty();
            live.Matches = 0;
            live.SessionDenied = 2;
            Check("job_session_denied_blocks", !JobProofEval.Evaluate(live, out err) && err == "sid_scan_inconclusive");
            JobScanStats trunc = JobScanStats.TrustedEmpty();
            trunc.EnumTruncated = true;
            Check("job_trunc", !JobProofEval.Evaluate(trunc, out err));
            Check("unknown_not_zero_process", !JobProofEval.Evaluate(live, out err));
            JobScanStats brk = JobScanStats.TrustedEmpty();
            brk.JobBreakawayOk = true;
            Check("job_breakaway_blocks", !JobProofEval.Evaluate(brk, out err) && err == "job_breakaway_allowed");
            JobScanStats own = JobScanStats.TrustedEmpty();
            own.JobOwnerKnown = false;
            Check("job_owner_unknown_blocks", !JobProofEval.Evaluate(own, out err) && err == "job_owner_unknown");
            Check("owner_sys", Native.OwnerSidTrusted("S-1-5-18"));
            Check("owner_ba", Native.OwnerSidTrusted("S-1-5-32-544"));
            Check("owner_foreign", !Native.OwnerSidTrusted("S-1-5-21-1-2-3-4"));
            Check("reparse_bit", Native.FileAttrsAreReparse(0x400));
            Check("reparse_none", !Native.FileAttrsAreReparse(0x10));
        }

        static FilterPlan TestPlan()
        {
            FilterSpec spec = SpecParser.ParseFilterSpec("{\"profileName\":\"nmzp.agent.machinetest01\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":4242}");
            return Planner.Build(spec, "S-1-15-2-1-2-3-4-5-6-7");
        }

        static void MachineTests()
        {
            FilterPlan plan = TestPlan();
            string owner = WfpConst.SidAdministrators;
            FakeWorld guarded = new FakeWorld();
            guarded.Guard = "journal_reparse";
            MachineResult gres = ApplyMachine.Run(guarded, plan, owner, null);
            Check("m_guard_no_mut", !gres.Ok && gres.Error == "journal_reparse" && guarded.FilterAddCount == 0 && guarded.ExemptionWriteCount == 0);

            FakeWorld w = new FakeWorld();
            w.PlantExemption("S-1-15-2-8", 7);
            MachineResult first = ApplyMachine.Run(w, plan, owner, null);
            Check("m_first_ok", first.Ok && first.Verified && first.Journal != null && first.Journal.LoopbackExemptionAddedByUs);
            Check("m_first_attr", w.ExemptionSnapshot()[ExemptionLogic.Find(w.ExemptionSnapshot(), "S-1-15-2-8")].Attributes == 7);
            bool owned = first.Journal.LoopbackExemptionAddedByUs;
            MachineResult second = ApplyMachine.Run(w, plan, owner, null);
            Check("m_repeat_keeps_own", second.Ok && second.Journal != null && second.Journal.LoopbackExemptionAddedByUs && owned);
            Check("m_repeat_not_takeover", second.Error == null);

            FakeWorld ext = new FakeWorld();
            ext.PlantExemption(plan.PackageSid, 0);
            ext.PlantExemption("S-1-15-2-8", 3);
            MachineResult blocked = ApplyMachine.Run(ext, plan, owner, null);
            Check("m_external_ex_refuse", !blocked.Ok && blocked.Error == "exemption_takeover_refused" && ext.FilterAddCount == 0);

            FakeWorld unk = new FakeWorld();
            FilterSnap foreign = new FilterSnap();
            foreign.Found = true;
            foreign.FilterKey = plan.Filters[0].FilterKey;
            foreign.LayerKey = plan.Filters[0].LayerKey;
            foreign.SubLayerKey = WfpGuids.SubLayer;
            foreign.ProviderKey = Guid.NewGuid();
            foreign.Flags = WfpConst.FwpmFilterFlagPersistent;
            foreign.ActionType = plan.Filters[0].ActionType;
            foreign.PackageSid = "S-1-15-2-9";
            unk.PlantFilter(foreign);
            MachineResult adopt = ApplyMachine.Run(unk, plan, owner, null);
            Check("m_no_adopt_unknown", !adopt.Ok && adopt.Error == "filter_exists_unknown" && unk.FilterAddCount == 0);

            FakeWorld jfail = new FakeWorld();
            jfail.FailJournalWrite = true;
            MachineResult jw = ApplyMachine.Run(jfail, plan, owner, null);
            Check("m_journal_fail_no_mut", !jw.Ok && jfail.FilterAddCount == 0 && jfail.ExemptionWriteCount == 0);

            FakeWorld corrupt = new FakeWorld();
            corrupt.JournalReadError = "journal_parse:truncated";
            MachineResult cj = ApplyMachine.Run(corrupt, plan, owner, null);
            Check("m_journal_corrupt_no_overwrite", !cj.Ok && cj.Error == "journal_parse:truncated" && corrupt.FilterAddCount == 0);

            FakeWorld denied = new FakeWorld();
            denied.JournalReadError = "journal_read:UnauthorizedAccessException";
            MachineResult dj = ApplyMachine.Run(denied, plan, owner, null);
            Check("m_journal_denied_no_overwrite", !dj.Ok && dj.Error.IndexOf("journal_read", StringComparison.Ordinal) >= 0 && denied.FilterAddCount == 0);

            FakeWorld wrong = new FakeWorld();
            ApplyMachine.Run(wrong, plan, owner, null);
            FilterSnap badW = SnapFromPlanned(plan.Filters[0]);
            badW.Weight = 1;
            wrong.PlantFilter(badW);
            MachineResult rw = ApplyMachine.Run(wrong, plan, owner, null);
            Check("m_reapply_wrong_weight", !rw.Ok && rw.Error != null && rw.Error.IndexOf("filter_weight", StringComparison.Ordinal) >= 0);

            FakeWorld race = new FakeWorld();
            race.PlantExemption("S-1-15-2-8", 1);
            race.ConcurrentRevokeSid = "S-1-15-2-8";
            MachineResult rc = ApplyMachine.Run(race, plan, owner, null);
            Check("m_concurrent_no_restore", !rc.Ok && rc.Error == "exemption_concurrent_change" && race.ExemptionWriteCount == 1);
            Check("m_concurrent_not_put_back", ExemptionLogic.Find(race.ExemptionSnapshot(), "S-1-15-2-8") < 0);

            FakeWorld attr = new FakeWorld();
            attr.PlantExemption("S-1-15-2-8", 7);
            attr.ConcurrentAttrSid = "S-1-15-2-8";
            attr.ConcurrentAttrValue = 11;
            MachineResult ac = ApplyMachine.Run(attr, plan, owner, null);
            Check("m_concurrent_attr_no_overwrite", !ac.Ok && ac.Error == "exemption_concurrent_change" && ac.Journal != null && ac.Journal.State != JournalState.Ready);
            Check("m_concurrent_attr_writes_once", attr.ExemptionWriteCount == 1);
            Check("m_concurrent_attr_kept", attr.ExemptionSnapshot()[ExemptionLogic.Find(attr.ExemptionSnapshot(), "S-1-15-2-8")].Attributes == 11);

            FakeWorld getFail = new FakeWorld();
            getFail.FilterGetFailKey = plan.Filters[0].FilterKey;
            getFail.FilterGetFailCount = 1;
            MachineResult gf = ApplyMachine.Run(getFail, plan, owner, null);
            Check("m_filterget_fail_not_absent", !gf.Ok && gf.Error == "injected_filter_get_fail" && getFail.FilterAddCount == 0);

            FakeWorld already = new FakeWorld();
            already.ProviderAddResult = WfpConst.FwpEAlreadyExists;
            MachineResult pe = ApplyMachine.Run(already, plan, owner, null);
            Check("m_already_exists_not_success", !pe.Ok && pe.Error != null && pe.Error.IndexOf("unverified", StringComparison.Ordinal) >= 0);

            FakeWorld ownProv = new FakeWorld();
            ownProv.PlantProvider("S-1-5-21-9-9-9-9", WfpConst.FwpmProviderFlagPersistent, true);
            MachineResult fp = ApplyMachine.Run(ownProv, plan, owner, null);
            Check("m_foreign_provider", !fp.Ok && fp.Error == "provider_foreign_owner" && ownProv.FilterAddCount == 0);

            InterruptResume(plan, owner);
            CleanupMachineTests(plan, owner);
        }

        static void InterruptResume(FilterPlan plan, string owner)
        {
            string[] phases = new string[]
            {
                "write_planned", "ensure_shared", "add_filters",
                "write_filters_installed", "write_exemption_pending", "add_exemption"
            };
            for (int i = 0; i < phases.Length; i++)
            {
                FakeWorld w = new FakeWorld();
                w.PlantExemption("S-1-15-2-8", 2);
                MachineResult stop = ApplyMachine.Run(w, plan, owner, phases[i]);
                Check("m_stop_" + phases[i], !stop.Ok && stop.Error == "stopped:" + phases[i]);
                MachineResult resume = ApplyMachine.Run(w, plan, owner, null);
                if (phases[i] == "add_filters")
                {
                    Check("m_resume_add_filters_noloadopt", !resume.Ok && resume.Error == "filter_exists_unknown");
                }
                else
                {
                    Check("m_resume_" + phases[i], resume.Ok && resume.Journal != null && resume.Journal.LoopbackExemptionAddedByUs);
                }
            }
        }

        static void CleanupMachineTests(FilterPlan plan, string owner)
        {
            FakeWorld w = new FakeWorld();
            w.PlantExemption("S-1-15-2-8", 4);
            MachineResult applied = ApplyMachine.Run(w, plan, owner, null);
            Check("c_setup", applied.Ok);
            CleanupSpec cs = new CleanupSpec();
            cs.ProfileName = plan.ProfileName;
            cs.JournalId = plan.JournalId;
            cs.JobKind = "named_job";
            cs.JobName = plan.JobNameLocal;
            w.JobStats = JobScanStats.TrustedEmpty();
            MachineResult clean = CleanupMachine.Run(w, plan, cs, null);
            Check("c_ok", clean.Ok && clean.Verified && clean.JournalDeleted && !clean.Installed);
            Check("c_filters_gone", w.FilterAddCount >= 3 && w.FilterDeleteCount == 3);
            Check("c_other_kept", ExemptionLogic.Contains(w.ExemptionSnapshot(), "S-1-15-2-8"));
            Check("c_ours_gone", !ExemptionLogic.Contains(w.ExemptionSnapshot(), plan.PackageSid));

            FakeWorld unknown = new FakeWorld();
            unknown.PlantExemption("S-1-15-2-8", 1);
            MachineResult a2 = ApplyMachine.Run(unknown, plan, owner, null);
            Check("c_unk_setup", a2.Ok);
            unknown.PlantExemption(plan.PackageSid, 9);
            JournalRecord jr;
            string e;
            unknown.JournalRead(plan.JournalId, out jr, out e);
            jr.LoopbackExemptionAddedByUs = false;
            jr.State = JournalState.FiltersInstalled;
            unknown.JournalWriteDurable(jr, out e);
            MachineResult bad = CleanupMachine.Run(unknown, plan, cs, null);
            Check("c_unknown_ex_keeps_block", !bad.Ok && bad.Error == "exemption_conflict_leave_block" && !bad.DeletedFilters);
            Check("c_unknown_filters_remain", unknown.FilterDeleteCount == 0);

            FakeWorld jdel = new FakeWorld();
            ApplyMachine.Run(jdel, plan, owner, null);
            jdel.FailJournalWrite = false;
            FakeWorld jdel2 = jdel;
            MachineResult c2 = CleanupMachine.Run(jdel2, plan, cs, "filters_absent");
            Check("c_stop_before_journal_del", !c2.Ok);

            FakeWorld jobfail = new FakeWorld();
            ApplyMachine.Run(jobfail, plan, owner, null);
            jobfail.JobError = "job_open_failed";
            jobfail.JobStats = JobScanStats.TrustedEmpty();
            jobfail.JobStats.JobMissing = true;
            MachineResult cj = CleanupMachine.Run(jobfail, plan, cs, null);
            Check("c_missing_job_keeps_filters", !cj.Ok && cj.Error == "job_open_failed" && jobfail.FilterDeleteCount == 0);

            FakeWorld unread = new FakeWorld();
            ApplyMachine.Run(unread, plan, owner, null);
            unread.JobStats = JobScanStats.TrustedEmpty();
            unread.JobStats.SystemDenied = 3;
            MachineResult cu = CleanupMachine.Run(unread, plan, cs, null);
            Check("c_unreadable_keeps_block", !cu.Ok && cu.Error == "sid_scan_inconclusive" && !cu.Verified && unread.FilterDeleteCount == 0);

            FakeHeldWorld heldBusy = new FakeHeldWorld();
            ApplyMachine.Run(heldBusy, plan, owner, null);
            heldBusy.HeldStats = JobScanStats.TrustedEmpty();
            heldBusy.HeldStats.JobAssignedProcesses = 2;
            heldBusy.HeldStats.JobNotEmpty = true;
            MachineResult hn = CleanupMachine.Run(heldBusy, plan, cs, null);
            Check("c_held_job_not_empty", !hn.Ok && hn.Error == "job_not_empty" && heldBusy.FilterDeleteCount == 0);

            FakeHeldWorld heldOk = new FakeHeldWorld();
            ApplyMachine.Run(heldOk, plan, owner, null);
            heldOk.HeldStats = JobScanStats.TrustedEmpty();
            MachineResult ho = CleanupMachine.Run(heldOk, plan, cs, null);
            Check("c_held_empty_skips_ppl", ho.Ok && ho.Verified);

            FakeWorld preGet = new FakeWorld();
            ApplyMachine.Run(preGet, plan, owner, null);
            preGet.JobStats = JobScanStats.TrustedEmpty();
            preGet.FilterGetFailKey = plan.Filters[0].FilterKey;
            preGet.FilterGetFailCount = 1;
            preGet.FilterGetFailSkip = 0;
            MachineResult pg = CleanupMachine.Run(preGet, plan, cs, null);
            Check("c_filterget_fail_pre_delete", !pg.Ok && !pg.Verified && pg.Error == "injected_filter_get_fail" && preGet.FilterDeleteCount == 0);

            FakeWorld postGet = new FakeWorld();
            ApplyMachine.Run(postGet, plan, owner, null);
            postGet.JobStats = JobScanStats.TrustedEmpty();
            postGet.FilterGetFailKey = plan.Filters[0].FilterKey;
            postGet.FilterGetFailCount = 1;
            postGet.FilterGetFailSkip = 1;
            MachineResult po = CleanupMachine.Run(postGet, plan, cs, null);
            Check("c_filterget_fail_post_delete", !po.Ok && !po.Verified && po.Error != null && po.Error.IndexOf("filter_absent_unverified", StringComparison.Ordinal) == 0 && postGet.FilterDeleteCount == 1);

            FakeWorld portW = new FakeWorld();
            ApplyMachine.Run(portW, plan, owner, null);
            portW.JobStats = JobScanStats.TrustedEmpty();
            FilterSpec wrongSpec = new FilterSpec();
            wrongSpec.ProfileName = plan.ProfileName;
            wrongSpec.GatewayAddress = "127.0.0.1";
            wrongSpec.GatewayPort = 1;
            FilterPlan wrongPlan = Planner.Build(wrongSpec, plan.PackageSid);
            MachineResult wp = CleanupMachine.Run(portW, wrongPlan, cs, null);
            Check("c_wrong_port_plan_keeps_filters", !wp.Ok && wp.Error == "journal_gateway_mismatch" && portW.FilterDeleteCount == 0);
        }

        static void LeaseTests()
        {
            string err;
            OwnedNetworkJobLease lease;
            if (!OwnedNetworkJobLease.TryCreate(out lease, out err))
            {
                Fail("lease_create:" + err);
                return;
            }
            try
            {
                Check("lease_state_created", lease.State == OwnedSessionState.Created);
                Check("lease_profile_prefix", Names.ProfileOk(lease.ProfileName));
                Check("lease_sid", lease.PackageSid != null && lease.PackageSid.StartsWith("S-1-15-2-", StringComparison.Ordinal));
                Check("lease_job_name", Names.JobNameOk(lease.JobName, lease.ProfileName));
                Check("lease_job_handle", lease.DangerousGetJobHandle() != IntPtr.Zero);
                Check("lease_folder_required", !string.IsNullOrEmpty(lease.ProfileFolder));
                Check("lease_job_dacl_present", JobDaclPresent(lease.DangerousGetJobHandle()));
                Check("lease_job_ui_required", JobUiRequiredPresent(lease.DangerousGetJobHandle()));
                Check("lease_job_no_breakaway", JobNoBreakaway(lease.DangerousGetJobHandle()));
                bool prep = lease.PrepareNetwork(4242, out err);
                Check("lease_prepare_not_bound", !prep && err == "lease_prepare_not_bound" && lease.State == OwnedSessionState.Created);
                bool b0 = lease.BindSuspendedProcess(IntPtr.Zero, out err);
                Check("lease_bind_zero", !b0 && err == "lease_bind_handle" && lease.State == OwnedSessionState.Faulted);
            }
            finally
            {
                if (lease != null) lease.Dispose();
            }

            OwnedNetworkJobLease lease2;
            if (!OwnedNetworkJobLease.TryCreate(out lease2, out err))
            {
                Fail("lease_create2:" + err);
                return;
            }
            try
            {
                bool bindCur = lease2.BindSuspendedProcess(SessionNative.GetCurrentProcess(), out err);
                Check("lease_bind_current_rejected", !bindCur && lease2.State == OwnedSessionState.Faulted);
                bool closed = lease2.CloseSession(out err);
                Check("lease_close_empty_after_fault", closed && lease2.State == OwnedSessionState.Closed);
            }
            finally
            {
                if (lease2 != null) lease2.Dispose();
            }

            OwnedNetworkJobLease lease3;
            if (!OwnedNetworkJobLease.TryCreate(out lease3, out err))
            {
                Fail("lease_create3:" + err);
                return;
            }
            string savedProfile = lease3.ProfileName;
            bool closeEmpty = lease3.CloseSession(out err);
            Check("lease_close_new_empty", closeEmpty && lease3.State == OwnedSessionState.Closed);
            IntPtr sid2 = IntPtr.Zero;
            int hrCreate = SessionNative.CreateAppContainerProfile(savedProfile, savedProfile, "nmzp-lease-recreate", IntPtr.Zero, 0, out sid2);
            if (sid2 != IntPtr.Zero) SessionNative.FreeSid(sid2);
            Check("lease_profile_recreate_after_close", hrCreate == 0);
            if (hrCreate == 0) SessionNative.DeleteAppContainerProfile(savedProfile);
            lease3.Dispose();

            SessionNative.SetLastError(0);
            string existName = "Local\\nmzp.agent.leaseexist01.job";
            IntPtr j1 = SessionNative.CreateJobObject(IntPtr.Zero, existName);
            SessionNative.SetLastError(0);
            IntPtr j2 = SessionNative.CreateJobObject(IntPtr.Zero, existName);
            uint already = unchecked((uint)Marshal.GetLastWin32Error());
            Check("lease_job_already_exists_detected", j1 != IntPtr.Zero && j2 != IntPtr.Zero && already == 183);
            if (j1 != IntPtr.Zero) SessionNative.CloseHandle(j1);
            if (j2 != IntPtr.Zero) SessionNative.CloseHandle(j2);

            LeasePrepareExceptionTests();
            Check("wfp_prepare_not_tested_nonadmin", !Native.IsElevatedAdmin());
        }

        static void LeasePrepareExceptionTests()
        {
            string err;
            OwnedNetworkJobLease lease;
            if (!OwnedNetworkJobLease.TryCreate(out lease, out err))
            {
                Fail("lease_exc_create:" + err);
                return;
            }
            string saved = lease.ProfileName;
            try
            {
                Check("lease_exc_enter_bound", lease.EnterBoundForSelfTest(out err));
                FakeHeldWorld boom = new FakeHeldWorld();
                boom.ThrowOnFilterAdd = true;
                boom.HeldStats = JobScanStats.TrustedEmpty();
                bool prep = lease.PrepareNetworkWithWorld(42424, boom, out err);
                Check("lease_exc_prepare_fail", !prep && err != null && err.IndexOf("prepare_exception", StringComparison.Ordinal) == 0);
                Check("lease_exc_network_modified", lease.NetworkModified && lease.State == OwnedSessionState.Faulted);
                FilterSpec spec = new FilterSpec();
                spec.ProfileName = lease.ProfileName;
                spec.GatewayAddress = "127.0.0.1";
                spec.GatewayPort = 42424;
                FilterPlan expected = Planner.Build(spec, lease.PackageSid);
                boom.ThrowOnFilterAdd = false;
                boom.FilterGetFailKey = expected.Filters[0].FilterKey;
                boom.FilterGetFailCount = 1;
                bool closed = lease.CloseSessionWithWorld(boom, out err);
                Check("lease_exc_cleanup_unverified", !closed && lease.State == OwnedSessionState.Faulted);
                IntPtr sidKeep = IntPtr.Zero;
                int hrKeep = SessionNative.CreateAppContainerProfile(saved, saved, "nmzp-lease-keep", IntPtr.Zero, 0, out sidKeep);
                if (sidKeep != IntPtr.Zero) SessionNative.FreeSid(sidKeep);
                Check("lease_exc_profile_kept", hrKeep != 0);
            }
            finally
            {
                SessionNative.DeleteAppContainerProfile(saved);
                if (lease != null) lease.Dispose();
            }

            OwnedNetworkJobLease leaseOk;
            if (!OwnedNetworkJobLease.TryCreate(out leaseOk, out err))
            {
                Fail("lease_port_create:" + err);
                return;
            }
            string savedOk = leaseOk.ProfileName;
            try
            {
                Check("lease_port_enter_bound", leaseOk.EnterBoundForSelfTest(out err));
                FakeHeldWorld world = new FakeHeldWorld();
                world.HeldStats = JobScanStats.TrustedEmpty();
                bool prepOk = leaseOk.PrepareNetworkWithWorld(42424, world, out err);
                Check("lease_prepare_uses_port", prepOk && leaseOk.State == OwnedSessionState.NetworkReady && leaseOk.NetworkModified);
                bool closedOk = leaseOk.CloseSessionWithWorld(world, out err);
                Check("lease_close_uses_prepared_port", closedOk && leaseOk.State == OwnedSessionState.Closed);
                IntPtr sid2 = IntPtr.Zero;
                int hrCreate = SessionNative.CreateAppContainerProfile(savedOk, savedOk, "nmzp-lease-port", IntPtr.Zero, 0, out sid2);
                if (sid2 != IntPtr.Zero) SessionNative.FreeSid(sid2);
                Check("lease_close_deleted_profile", hrCreate == 0);
                if (hrCreate == 0) SessionNative.DeleteAppContainerProfile(savedOk);
            }
            finally
            {
                if (leaseOk != null) leaseOk.Dispose();
            }
        }

        static bool JobDaclPresent(IntPtr job)
        {
            if (job == IntPtr.Zero) return false;
            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr sd;
            uint st = Native.GetSecurityInfo(
                job,
                WfpConst.SeKernelObject,
                WfpConst.OwnerSecurityInformation | WfpConst.DaclSecurityInformation,
                out owner,
                out group,
                out dacl,
                out sacl,
                out sd);
            if (st != 0 || sd == IntPtr.Zero) return false;
            try
            {
                return dacl != IntPtr.Zero;
            }
            finally
            {
                Native.LocalFree(sd);
            }
        }

        static bool JobUiRequiredPresent(IntPtr job)
        {
            if (job == IntPtr.Zero) return false;
            int size = Marshal.SizeOf(typeof(JobObjectBasicUiRestrictions));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectBasicUIRestrictions, buf, (uint)size, IntPtr.Zero))
                {
                    return false;
                }
                JobObjectBasicUiRestrictions got = (JobObjectBasicUiRestrictions)Marshal.PtrToStructure(buf, typeof(JobObjectBasicUiRestrictions));
                return (got.UIRestrictionsClass & WfpConst.JobUiRequired) == WfpConst.JobUiRequired;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static bool JobNoBreakaway(IntPtr job)
        {
            if (job == IntPtr.Zero) return false;
            int size = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!SessionNative.QueryInformationJobObject(job, WfpConst.JobObjectExtendedLimitInformation, buf, (uint)size, IntPtr.Zero))
                {
                    return false;
                }
                JobObjectExtendedLimitInformation got = (JobObjectExtendedLimitInformation)Marshal.PtrToStructure(buf, typeof(JobObjectExtendedLimitInformation));
                uint flags = got.BasicLimitInformation.LimitFlags;
                if ((flags & WfpConst.JobObjectLimitKillOnJobClose) == 0) return false;
                if ((flags & WfpConst.JobObjectLimitBreakawayOk) != 0) return false;
                if ((flags & WfpConst.JobObjectLimitSilentBreakawayOk) != 0) return false;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static void DeriveTests()
        {
            string sid;
            string err;
            bool ok = Native.TryDerivePackageSid("nmzp.agent.selftest01", out sid, out err);
            Check("derive_ok", ok && sid != null && sid.StartsWith("S-1-15-2-", StringComparison.Ordinal));
            string sid2;
            Native.TryDerivePackageSid("nmzp.agent.selftest01", out sid2, out err);
            Check("derive_stable", ok && sid == sid2);
            string sid3;
            Native.TryDerivePackageSid("nmzp.agent.selftest02", out sid3, out err);
            Check("derive_unique", sid3 != sid);
        }

        static void NonAdminTests()
        {
            if (Native.IsElevatedAdmin())
            {
                Pass("nonadmin_skipped_because_elevated");
                return;
            }
            FilterSpec spec = SpecParser.ParseFilterSpec("{\"profileName\":\"nmzp.agent.selftest01\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":43210}");
            string json = "{\"profileName\":\"nmzp.agent.selftest01\",\"gatewayAddress\":\"127.0.0.1\",\"gatewayPort\":43210}";
            int beforeMut = Native.MutationSum();
            int beforeGet = Native.ExemptionGetCalls;
            string captured;
            int rc = Capture(delegate { return Commands.Apply(json); }, out captured);
            Check("apply_rc_requires_admin", rc == 4);
            Check("apply_error_requires_admin", captured.IndexOf("requires_admin", StringComparison.Ordinal) >= 0);
            Check("apply_verified_false", captured.IndexOf("\"verified\":false", StringComparison.Ordinal) >= 0);
            Check("apply_changed_false", captured.IndexOf("\"changed\":false", StringComparison.Ordinal) >= 0);
            Check("apply_no_mutation", Native.MutationSum() == beforeMut);
            Check("apply_no_exemption_read", Native.ExemptionGetCalls == beforeGet);

            string clean = "{\"profileName\":\"nmzp.agent.selftest01\",\"journalId\":\"" + Planner.Build(spec, "S-1-15-2-1").JournalId + "\",\"jobEmptyProof\":{\"kind\":\"named_job\",\"jobName\":\"Local\\\\nmzp.agent.selftest01.job\"}}";
            rc = Capture(delegate { return Commands.Cleanup(clean); }, out captured);
            Check("cleanup_rc_requires_admin", rc == 4);
            Check("cleanup_error_requires_admin", captured.IndexOf("requires_admin", StringComparison.Ordinal) >= 0);
            Check("cleanup_no_mutation", Native.MutationSum() == beforeMut);
        }

        delegate int Cmd();

        static int Capture(Cmd cmd, out string text)
        {
            TextWriter old = Console.Out;
            StringWriter sw = new StringWriter();
            Console.SetOut(sw);
            try
            {
                int rc = cmd();
                text = sw.ToString();
                return rc;
            }
            finally
            {
                Console.SetOut(old);
            }
        }

        static void ExpectOkSpec(string json)
        {
            try
            {
                SpecParser.ParseFilterSpec(json);
                Pass("spec_ok");
            }
            catch (Exception ex)
            {
                Fail("spec_ok:" + ex.Message);
            }
        }

        static void ExpectBadSpec(string name, string json)
        {
            try
            {
                SpecParser.ParseFilterSpec(json);
                Fail("spec_bad_" + name);
            }
            catch (JsonException)
            {
                Pass("spec_bad_" + name);
            }
            catch (Exception ex)
            {
                Fail("spec_bad_" + name + ":" + ex.GetType().Name);
            }
        }

        static string Join(string[] a)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < a.Length; i++)
            {
                if (i > 0) sb.Append('|');
                sb.Append(a[i]);
            }
            return sb.ToString();
        }

        static void Check(string name, bool ok)
        {
            names.Add(name);
            if (ok) { }
            else Fail(name);
        }

        static void Pass(string name)
        {
            names.Add(name);
        }

        static void Fail(string name)
        {
            names.Add("FAIL:" + name);
            fails++;
            Console.Error.WriteLine("SELFTEST_FAIL " + name);
        }

        static void Note(string s)
        {
            Console.Error.WriteLine("SELFTEST_NOTE " + s);
        }
    }
}
