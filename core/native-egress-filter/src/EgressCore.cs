using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Nmzp.NativeEgressFilter
{
    internal sealed class FilterSpec
    {
        public string ProfileName;
        public string GatewayAddress;
        public int GatewayPort;
    }

    internal sealed class CleanupSpec
    {
        public string ProfileName;
        public string JournalId;
        public string JobKind;
        public string JobName;
    }

    internal sealed class ConditionSpec
    {
        public Guid FieldKey;
        public int MatchType;
        public int ValueType;
        public string Sid;
        public uint U32;
        public ushort U16;
        public byte U8;

        public static ConditionSpec SidEq(Guid field, string sid)
        {
            ConditionSpec c = new ConditionSpec();
            c.FieldKey = field;
            c.MatchType = WfpConst.FwpMatchEqual;
            c.ValueType = WfpConst.FwpSid;
            c.Sid = sid;
            return c;
        }

        public static ConditionSpec U8Eq(Guid field, byte v)
        {
            ConditionSpec c = new ConditionSpec();
            c.FieldKey = field;
            c.MatchType = WfpConst.FwpMatchEqual;
            c.ValueType = WfpConst.FwpUint8;
            c.U8 = v;
            return c;
        }

        public static ConditionSpec U16Eq(Guid field, ushort v)
        {
            ConditionSpec c = new ConditionSpec();
            c.FieldKey = field;
            c.MatchType = WfpConst.FwpMatchEqual;
            c.ValueType = WfpConst.FwpUint16;
            c.U16 = v;
            return c;
        }

        public static ConditionSpec U32Eq(Guid field, uint v)
        {
            ConditionSpec c = new ConditionSpec();
            c.FieldKey = field;
            c.MatchType = WfpConst.FwpMatchEqual;
            c.ValueType = WfpConst.FwpUint32;
            c.U32 = v;
            return c;
        }

        public static bool Equal(ConditionSpec a, ConditionSpec b)
        {
            if (a == null || b == null) return false;
            if (a.FieldKey != b.FieldKey) return false;
            if (a.MatchType != b.MatchType) return false;
            if (a.ValueType != b.ValueType) return false;
            if (a.ValueType == WfpConst.FwpSid)
            {
                return string.Equals(a.Sid, b.Sid, StringComparison.Ordinal);
            }
            if (a.ValueType == WfpConst.FwpUint8) return a.U8 == b.U8;
            if (a.ValueType == WfpConst.FwpUint16) return a.U16 == b.U16;
            if (a.ValueType == WfpConst.FwpUint32) return a.U32 == b.U32;
            return false;
        }

        public static bool KnownValueType(int t)
        {
            return t == WfpConst.FwpSid || t == WfpConst.FwpUint8 || t == WfpConst.FwpUint16 || t == WfpConst.FwpUint32;
        }

        public static bool KnownField(Guid g)
        {
            return g == WfpGuids.CondAlePackageId
                || g == WfpGuids.CondIpProtocol
                || g == WfpGuids.CondIpRemoteAddress
                || g == WfpGuids.CondIpRemotePort;
        }
    }

    internal sealed class PlannedFilter
    {
        public string Role;
        public Guid FilterKey;
        public string Layer;
        public Guid LayerKey;
        public string Action;
        public uint ActionType;
        public byte Weight;
        public int WeightType;
        public bool ClearActionRight;
        public bool Persistent;
        public string[] Conditions;
        public ConditionSpec[] Expected;
    }

    internal sealed class FilterPlan
    {
        public string ProfileName;
        public string PackageSid;
        public string GatewayAddress;
        public int GatewayPort;
        public Guid ProviderKey;
        public Guid SubLayerKey;
        public ushort SubLayerWeight;
        public string JournalId;
        public string JobNameLocal;
        public string JobNameGlobal;
        public PlannedFilter[] Filters;
        public string ArbitrationNote;
    }

    internal sealed class JournalRecord
    {
        public string Schema;
        public string JournalId;
        public string ProfileName;
        public string PackageSid;
        public string GatewayAddress;
        public int GatewayPort;
        public string OwnerSid;
        public string ProviderKey;
        public string SubLayerKey;
        public string State;
        public bool LoopbackExemptionAddedByUs;
        public string CreatedUtc;
        public List<JournalFilter> Filters = new List<JournalFilter>();
    }

    internal sealed class JournalFilter
    {
        public string Role;
        public string FilterKey;
        public string FilterId;
        public string Layer;
        public string Action;
    }

    internal static class Names
    {
        public const string ProfilePrefix = "nmzp.agent.";
        public const string JournalSchema = "nmzp.native-egress-filter.journal.v1";
        public const string HelperName = "NmzpNativeEgressFilter";
        static readonly Regex ProfileRx = new Regex(
            @"^nmzp\.agent\.[A-Za-z0-9]{8,32}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);
        static readonly Regex JobRx = new Regex(
            @"^(Global|Local)\\nmzp\.agent\.[A-Za-z0-9]{8,32}\.job$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static bool ProfileOk(string name)
        {
            return name != null && name.Length <= 64 && ProfileRx.IsMatch(name);
        }

        public static bool JobNameOk(string jobName, string profileName)
        {
            if (jobName == null || profileName == null) return false;
            if (!JobRx.IsMatch(jobName)) return false;
            string nonce = profileName.Substring(ProfilePrefix.Length);
            string local = "Local\\nmzp.agent." + nonce + ".job";
            string global = "Global\\nmzp.agent." + nonce + ".job";
            return string.Equals(jobName, local, StringComparison.Ordinal)
                || string.Equals(jobName, global, StringComparison.Ordinal);
        }

        public static string NonceOf(string profileName)
        {
            if (profileName == null || !profileName.StartsWith(ProfilePrefix, StringComparison.Ordinal))
            {
                return null;
            }
            return profileName.Substring(ProfilePrefix.Length);
        }

        public static string DefaultJournalDir()
        {
            string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(pd, "NMZP", "native-egress-filter", "journal");
        }

        public static string JournalPath(string dir, string journalId)
        {
            return Path.Combine(dir, "j-" + journalId + ".json");
        }
    }

    internal static class SpecParser
    {
        public static FilterSpec ParseFilterSpec(string json)
        {
            if (json == null || json.Length > Json.MaxSpecBytes)
            {
                throw new JsonException("spec_size");
            }
            JsonObject o = Json.AsObject(Json.Parse(json), "spec");
            Json.RejectUnknown(o, "profileName", "gatewayAddress", "gatewayPort");
            FilterSpec s = new FilterSpec();
            s.ProfileName = Json.ReqString(o, "profileName");
            s.GatewayAddress = Json.ReqString(o, "gatewayAddress");
            s.GatewayPort = Json.ReqInt(o, "gatewayPort");
            ValidateFilter(s);
            return s;
        }

        public static CleanupSpec ParseCleanupSpec(string json)
        {
            if (json == null || json.Length > Json.MaxSpecBytes)
            {
                throw new JsonException("spec_size");
            }
            JsonObject o = Json.AsObject(Json.Parse(json), "spec");
            Json.RejectUnknown(o, "profileName", "journalId", "jobEmptyProof");
            CleanupSpec s = new CleanupSpec();
            s.ProfileName = Json.ReqString(o, "profileName");
            s.JournalId = Json.ReqString(o, "journalId");
            JsonObject proof = Json.ReqObject(o, "jobEmptyProof");
            Json.RejectUnknown(proof, "kind", "jobName");
            s.JobKind = Json.ReqString(proof, "kind");
            if (!string.Equals(s.JobKind, "named_job", StringComparison.Ordinal))
            {
                throw new JsonException("jobEmptyProof.kind:only_named_job");
            }
            s.JobName = Json.ReqString(proof, "jobName");
            if (!Names.ProfileOk(s.ProfileName))
            {
                throw new JsonException("profileName");
            }
            if (!GuidOk(s.JournalId))
            {
                throw new JsonException("journalId");
            }
            if (!Names.JobNameOk(s.JobName, s.ProfileName))
            {
                throw new JsonException("jobName");
            }
            return s;
        }

        public static void ValidateFilter(FilterSpec s)
        {
            if (!Names.ProfileOk(s.ProfileName))
            {
                throw new JsonException("profileName");
            }
            if (!string.Equals(s.GatewayAddress, "127.0.0.1", StringComparison.Ordinal))
            {
                throw new JsonException("gatewayAddress:exact_127.0.0.1_required");
            }
            if (s.GatewayPort < 1 || s.GatewayPort > 65535)
            {
                throw new JsonException("gatewayPort");
            }
        }

        static bool GuidOk(string g)
        {
            if (string.IsNullOrEmpty(g) || g.Length > 40) return false;
            try
            {
                new Guid(g);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    internal static class Planner
    {
        static readonly Guid Ns = new Guid("c5e18b2d-4a70-4f93-9c1e-6b8d2a14e057");

        public static FilterPlan Build(FilterSpec spec, string packageSid)
        {
            if (spec == null) throw new ArgumentNullException("spec");
            if (string.IsNullOrEmpty(packageSid)) throw new ArgumentException("packageSid");
            string nonce = Names.NonceOf(spec.ProfileName);
            FilterPlan p = new FilterPlan();
            p.ProfileName = spec.ProfileName;
            p.PackageSid = packageSid;
            p.GatewayAddress = spec.GatewayAddress;
            p.GatewayPort = spec.GatewayPort;
            p.ProviderKey = WfpGuids.Provider;
            p.SubLayerKey = WfpGuids.SubLayer;
            p.SubLayerWeight = WfpConst.SubLayerWeight;
            p.JournalId = NameGuid("journal|" + spec.ProfileName).ToString("D");
            p.JobNameLocal = "Local\\nmzp.agent." + nonce + ".job";
            p.JobNameGlobal = "Global\\nmzp.agent." + nonce + ".job";
            p.ArbitrationNote =
                "permit_is_soft_no_CLEAR_ACTION_RIGHT; filter_block_is_hard_by_default; packageId_only";
            p.Filters = new PlannedFilter[]
            {
                AllowV4(spec, packageSid),
                BlockV4(spec, packageSid),
                BlockV6(spec, packageSid)
            };
            return p;
        }

        static PlannedFilter AllowV4(FilterSpec spec, string sid)
        {
            PlannedFilter f = new PlannedFilter();
            f.Role = "v4_allow_tcp_gateway";
            f.FilterKey = NameGuid("filter|" + spec.ProfileName + "|v4_allow_tcp_gateway|" + spec.GatewayPort.ToString(CultureInfo.InvariantCulture));
            f.Layer = "ALE_AUTH_CONNECT_V4";
            f.LayerKey = WfpGuids.LayerAleAuthConnectV4;
            f.Action = "permit";
            f.ActionType = WfpConst.FwpActionPermit;
            f.Weight = WfpConst.WeightAllow;
            f.WeightType = WfpConst.FwpUint8;
            f.ClearActionRight = false;
            f.Persistent = true;
            f.Conditions = new string[]
            {
                "ALE_PACKAGE_ID==" + sid,
                "IP_PROTOCOL==TCP",
                "IP_REMOTE_ADDRESS==127.0.0.1",
                "IP_REMOTE_PORT==" + spec.GatewayPort.ToString(CultureInfo.InvariantCulture)
            };
            f.Expected = new ConditionSpec[]
            {
                ConditionSpec.SidEq(WfpGuids.CondAlePackageId, sid),
                ConditionSpec.U8Eq(WfpGuids.CondIpProtocol, WfpConst.IpProtoTcp),
                ConditionSpec.U32Eq(WfpGuids.CondIpRemoteAddress, WfpConst.Ipv4LoopbackHostOrder),
                ConditionSpec.U16Eq(WfpGuids.CondIpRemotePort, (ushort)spec.GatewayPort)
            };
            return f;
        }

        static PlannedFilter BlockV4(FilterSpec spec, string sid)
        {
            PlannedFilter f = new PlannedFilter();
            f.Role = "v4_block_rest";
            f.FilterKey = NameGuid("filter|" + spec.ProfileName + "|v4_block_rest");
            f.Layer = "ALE_AUTH_CONNECT_V4";
            f.LayerKey = WfpGuids.LayerAleAuthConnectV4;
            f.Action = "block";
            f.ActionType = WfpConst.FwpActionBlock;
            f.Weight = WfpConst.WeightBlock;
            f.WeightType = WfpConst.FwpUint8;
            f.ClearActionRight = false;
            f.Persistent = true;
            f.Conditions = new string[] { "ALE_PACKAGE_ID==" + sid };
            f.Expected = new ConditionSpec[] { ConditionSpec.SidEq(WfpGuids.CondAlePackageId, sid) };
            return f;
        }

        static PlannedFilter BlockV6(FilterSpec spec, string sid)
        {
            PlannedFilter f = new PlannedFilter();
            f.Role = "v6_block_all";
            f.FilterKey = NameGuid("filter|" + spec.ProfileName + "|v6_block_all");
            f.Layer = "ALE_AUTH_CONNECT_V6";
            f.LayerKey = WfpGuids.LayerAleAuthConnectV6;
            f.Action = "block";
            f.ActionType = WfpConst.FwpActionBlock;
            f.Weight = WfpConst.WeightBlock;
            f.WeightType = WfpConst.FwpUint8;
            f.ClearActionRight = false;
            f.Persistent = true;
            f.Conditions = new string[] { "ALE_PACKAGE_ID==" + sid };
            f.Expected = new ConditionSpec[] { ConditionSpec.SidEq(WfpGuids.CondAlePackageId, sid) };
            return f;
        }

        public static Guid NameGuid(string name)
        {
            byte[] ns = Ns.ToByteArray();
            byte[] n = Encoding.UTF8.GetBytes(name);
            byte[] buf = new byte[ns.Length + n.Length];
            Buffer.BlockCopy(ns, 0, buf, 0, ns.Length);
            Buffer.BlockCopy(n, 0, buf, ns.Length, n.Length);
            byte[] hash;
            using (SHA256 sha = SHA256.Create())
            {
                hash = sha.ComputeHash(buf);
            }
            byte[] g = new byte[16];
            Buffer.BlockCopy(hash, 0, g, 0, 16);
            // Microsoft Guid.ToByteArray: time_hi_and_version is little-endian at [6],[7].
            g[7] = (byte)((g[7] & 0x0F) | 0x50);
            g[8] = (byte)((g[8] & 0x3F) | 0x80);
            return new Guid(g);
        }

        public static string ToRedactedJson(FilterPlan p, string command, bool ok, string error)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"ok\":");
            sb.Append(ok ? "true" : "false");
            sb.Append(",\"command\":");
            sb.Append(Json.Escape(command));
            sb.Append(",\"installed\":false");
            sb.Append(",\"verified\":false");
            sb.Append(",\"changed\":false");
            if (error != null)
            {
                sb.Append(",\"error\":");
                sb.Append(Json.Escape(error));
            }
            if (p != null)
            {
                sb.Append(",\"profileName\":");
                sb.Append(Json.Escape(p.ProfileName));
                sb.Append(",\"packageSid\":");
                sb.Append(Json.Escape(p.PackageSid));
                sb.Append(",\"gatewayAddress\":");
                sb.Append(Json.Escape(p.GatewayAddress));
                sb.Append(",\"gatewayPort\":");
                sb.Append(p.GatewayPort.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"journalId\":");
                sb.Append(Json.Escape(p.JournalId));
                sb.Append(",\"providerKey\":");
                sb.Append(Json.Escape(p.ProviderKey.ToString("D")));
                sb.Append(",\"subLayerKey\":");
                sb.Append(Json.Escape(p.SubLayerKey.ToString("D")));
                sb.Append(",\"subLayerWeight\":");
                sb.Append(p.SubLayerWeight.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"clearActionRight\":false");
                sb.Append(",\"sessionDynamic\":false");
                sb.Append(",\"persistent\":true");
                sb.Append(",\"jobNameContract\":{\"local\":");
                sb.Append(Json.Escape(p.JobNameLocal));
                sb.Append(",\"global\":");
                sb.Append(Json.Escape(p.JobNameGlobal));
                sb.Append("}");
                sb.Append(",\"arbitration\":");
                sb.Append(Json.Escape(p.ArbitrationNote));
                sb.Append(",\"filters\":[");
                for (int i = 0; i < p.Filters.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    PlannedFilter f = p.Filters[i];
                    sb.Append("{\"role\":");
                    sb.Append(Json.Escape(f.Role));
                    sb.Append(",\"filterKey\":");
                    sb.Append(Json.Escape(f.FilterKey.ToString("D")));
                    sb.Append(",\"layer\":");
                    sb.Append(Json.Escape(f.Layer));
                    sb.Append(",\"action\":");
                    sb.Append(Json.Escape(f.Action));
                    sb.Append(",\"weight\":");
                    sb.Append(f.Weight.ToString(CultureInfo.InvariantCulture));
                    sb.Append(",\"clearActionRight\":");
                    sb.Append(f.ClearActionRight ? "true" : "false");
                    sb.Append(",\"persistent\":");
                    sb.Append(f.Persistent ? "true" : "false");
                    sb.Append(",\"conditions\":[");
                    for (int c = 0; c < f.Conditions.Length; c++)
                    {
                        if (c > 0) sb.Append(',');
                        sb.Append(Json.Escape(f.Conditions[c]));
                    }
                    sb.Append("]}");
                }
                sb.Append(']');
                sb.Append(",\"ids\":{\"journalId\":");
                sb.Append(Json.Escape(p.JournalId));
                sb.Append(",\"providerKey\":");
                sb.Append(Json.Escape(p.ProviderKey.ToString("D")));
                sb.Append(",\"subLayerKey\":");
                sb.Append(Json.Escape(p.SubLayerKey.ToString("D")));
                sb.Append("}");
            }
            sb.Append('}');
            return sb.ToString();
        }
    }

    internal static class JournalState
    {
        public const string Planned = "planned";
        public const string FiltersInstalled = "filters_installed";
        public const string ExemptionPending = "exemption_pending";
        public const string Ready = "ready";

        public static bool AllowsResumeFilter(string state)
        {
            return state == FiltersInstalled || state == ExemptionPending || state == Ready;
        }

        public static bool ClaimsExemption(JournalRecord r)
        {
            if (r == null) return false;
            if (r.LoopbackExemptionAddedByUs) return true;
            return r.State == Ready || r.State == ExemptionPending;
        }
    }

    internal static class JournalIo
    {
        public static string Serialize(JournalRecord r)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"schema\":");
            sb.Append(Json.Escape(r.Schema));
            sb.Append(",\"journalId\":");
            sb.Append(Json.Escape(r.JournalId));
            sb.Append(",\"createdUtc\":");
            sb.Append(Json.Escape(r.CreatedUtc));
            sb.Append(",\"profileName\":");
            sb.Append(Json.Escape(r.ProfileName));
            sb.Append(",\"packageSid\":");
            sb.Append(Json.Escape(r.PackageSid));
            sb.Append(",\"gatewayAddress\":");
            sb.Append(Json.Escape(r.GatewayAddress));
            sb.Append(",\"gatewayPort\":");
            sb.Append(r.GatewayPort.ToString(CultureInfo.InvariantCulture));
            sb.Append(",\"ownerSid\":");
            sb.Append(Json.Escape(r.OwnerSid));
            sb.Append(",\"providerKey\":");
            sb.Append(Json.Escape(r.ProviderKey));
            sb.Append(",\"subLayerKey\":");
            sb.Append(Json.Escape(r.SubLayerKey));
            sb.Append(",\"state\":");
            sb.Append(Json.Escape(r.State));
            sb.Append(",\"loopbackExemptionAddedByUs\":");
            sb.Append(r.LoopbackExemptionAddedByUs ? "true" : "false");
            sb.Append(",\"filters\":[");
            for (int i = 0; i < r.Filters.Count; i++)
            {
                if (i > 0) sb.Append(',');
                JournalFilter f = r.Filters[i];
                sb.Append("{\"role\":");
                sb.Append(Json.Escape(f.Role));
                sb.Append(",\"filterKey\":");
                sb.Append(Json.Escape(f.FilterKey));
                sb.Append(",\"filterId\":");
                sb.Append(Json.Escape(f.FilterId ?? ""));
                sb.Append(",\"layer\":");
                sb.Append(Json.Escape(f.Layer));
                sb.Append(",\"action\":");
                sb.Append(Json.Escape(f.Action));
                sb.Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        public static JournalRecord FromPlan(FilterPlan p, string ownerSid, string state)
        {
            JournalRecord r = new JournalRecord();
            r.Schema = Names.JournalSchema;
            r.JournalId = p.JournalId;
            r.CreatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            r.ProfileName = p.ProfileName;
            r.PackageSid = p.PackageSid;
            r.GatewayAddress = p.GatewayAddress;
            r.GatewayPort = p.GatewayPort;
            r.OwnerSid = ownerSid;
            r.ProviderKey = p.ProviderKey.ToString("D");
            r.SubLayerKey = p.SubLayerKey.ToString("D");
            r.State = state;
            r.LoopbackExemptionAddedByUs = false;
            for (int i = 0; i < p.Filters.Length; i++)
            {
                JournalFilter jf = new JournalFilter();
                jf.Role = p.Filters[i].Role;
                jf.FilterKey = p.Filters[i].FilterKey.ToString("D");
                jf.FilterId = "";
                jf.Layer = p.Filters[i].Layer;
                jf.Action = p.Filters[i].Action;
                r.Filters.Add(jf);
            }
            return r;
        }

        public static void PreserveOwnership(JournalRecord prior, JournalRecord next)
        {
            if (prior == null || next == null) return;
            if (prior.LoopbackExemptionAddedByUs) next.LoopbackExemptionAddedByUs = true;
            if (!string.IsNullOrEmpty(prior.CreatedUtc)) next.CreatedUtc = prior.CreatedUtc;
            if (!string.IsNullOrEmpty(prior.OwnerSid) && string.IsNullOrEmpty(next.OwnerSid))
            {
                next.OwnerSid = prior.OwnerSid;
            }
        }

        public static bool MatchesPlan(JournalRecord r, FilterPlan p, out string error)
        {
            error = null;
            if (r == null || p == null)
            {
                error = "journal_null";
                return false;
            }
            if (!string.Equals(r.JournalId, p.JournalId, StringComparison.Ordinal))
            {
                error = "journal_id_mismatch";
                return false;
            }
            if (!string.Equals(r.ProfileName, p.ProfileName, StringComparison.Ordinal))
            {
                error = "journal_profile_mismatch";
                return false;
            }
            if (!string.Equals(r.PackageSid, p.PackageSid, StringComparison.Ordinal))
            {
                error = "journal_sid_mismatch";
                return false;
            }
            if (!string.Equals(r.GatewayAddress, p.GatewayAddress, StringComparison.Ordinal) || r.GatewayPort != p.GatewayPort)
            {
                error = "journal_gateway_mismatch";
                return false;
            }
            if (!string.Equals(r.ProviderKey, p.ProviderKey.ToString("D"), StringComparison.Ordinal)
                || !string.Equals(r.SubLayerKey, p.SubLayerKey.ToString("D"), StringComparison.Ordinal))
            {
                error = "journal_shared_mismatch";
                return false;
            }
            if (r.Filters.Count != p.Filters.Length)
            {
                error = "journal_filter_count";
                return false;
            }
            for (int i = 0; i < p.Filters.Length; i++)
            {
                bool found = false;
                string want = p.Filters[i].FilterKey.ToString("D");
                for (int j = 0; j < r.Filters.Count; j++)
                {
                    if (string.Equals(r.Filters[j].FilterKey, want, StringComparison.Ordinal)
                        && string.Equals(r.Filters[j].Role, p.Filters[i].Role, StringComparison.Ordinal))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    error = "journal_filter_key_mismatch";
                    return false;
                }
            }
            return true;
        }

        public static bool IsAbsentError(string error)
        {
            return error == "journal_missing";
        }

        public static bool TryRead(string path, out JournalRecord r, out string error)
        {
            r = null;
            error = null;
            try
            {
                if (!File.Exists(path))
                {
                    error = "journal_missing";
                    return false;
                }
                string json = File.ReadAllText(path, Encoding.UTF8);
                r = ParseLoose(json);
                return true;
            }
            catch (JsonException ex)
            {
                error = "journal_parse:" + ex.Message;
                return false;
            }
            catch (Exception ex)
            {
                error = "journal_read:" + ex.GetType().Name;
                return false;
            }
        }

        public static JournalRecord ParseLoose(string json)
        {
            JsonObject o = Json.AsObject(Json.Parse(json), "journal");
            Json.RejectUnknown(o,
                "schema", "journalId", "createdUtc", "profileName", "packageSid",
                "gatewayAddress", "gatewayPort", "ownerSid", "providerKey", "subLayerKey",
                "state", "loopbackExemptionAddedByUs", "filters");
            JournalRecord r = new JournalRecord();
            r.Schema = Json.ReqString(o, "schema");
            if (!string.Equals(r.Schema, Names.JournalSchema, StringComparison.Ordinal))
            {
                throw new JsonException("journal_schema");
            }
            r.JournalId = Json.ReqString(o, "journalId");
            r.CreatedUtc = Json.ReqString(o, "createdUtc");
            r.ProfileName = Json.ReqString(o, "profileName");
            r.PackageSid = Json.ReqString(o, "packageSid");
            r.GatewayAddress = Json.ReqString(o, "gatewayAddress");
            r.GatewayPort = Json.ReqInt(o, "gatewayPort");
            r.OwnerSid = Json.ReqString(o, "ownerSid");
            r.ProviderKey = Json.ReqString(o, "providerKey");
            r.SubLayerKey = Json.ReqString(o, "subLayerKey");
            r.State = Json.ReqString(o, "state");
            object flag;
            if (!o.Map.TryGetValue("loopbackExemptionAddedByUs", out flag) || !(flag is bool))
            {
                throw new JsonException("loopbackExemptionAddedByUs");
            }
            r.LoopbackExemptionAddedByUs = (bool)flag;
            object filtersObj;
            if (!o.Map.TryGetValue("filters", out filtersObj))
            {
                throw new JsonException("missing:filters");
            }
            JsonObject arrHolder = filtersObj as JsonObject;
            if (arrHolder != null)
            {
                throw new JsonException("filters_not_array");
            }
            List<object> arr = filtersObj as List<object>;
            if (arr == null)
            {
                throw new JsonException("filters_not_array");
            }
            for (int i = 0; i < arr.Count; i++)
            {
                JsonObject fo = Json.AsObject(arr[i], "filter");
                Json.RejectUnknown(fo, "role", "filterKey", "filterId", "layer", "action");
                JournalFilter jf = new JournalFilter();
                jf.Role = Json.ReqString(fo, "role");
                jf.FilterKey = Json.ReqString(fo, "filterKey");
                jf.FilterId = Json.ReqString(fo, "filterId");
                jf.Layer = Json.ReqString(fo, "layer");
                jf.Action = Json.ReqString(fo, "action");
                r.Filters.Add(jf);
            }
            if (r.Filters.Count != 3)
            {
                throw new JsonException("filters_count");
            }
            return r;
        }

        public static bool DurableWrite(string path, string json, out string error)
        {
            error = null;
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                {
                    error = "journal_dir_missing";
                    return false;
                }
                string tmp = path + ".tmp";
                string bak = path + ".bak";
                if (!RejectUnsafeExisting(tmp, out error)) return false;
                if (!RejectUnsafeExisting(bak, out error)) return false;
                if (!RejectUnsafeExisting(path, out error)) return false;
                byte[] bytes = Encoding.UTF8.GetBytes(json);
                using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush(true);
                }
                if (File.Exists(path))
                {
                    File.Replace(tmp, path, bak);
                    string ign;
                    Delete(bak, out ign);
                }
                else
                {
                    File.Move(tmp, path);
                }
                JournalRecord back;
                string readErr;
                if (!TryRead(path, out back, out readErr) || back == null)
                {
                    error = "journal_reread_failed";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = "journal_write:" + ex.GetType().Name;
                return false;
            }
        }

        public static bool Delete(string path, out string error)
        {
            error = null;
            try
            {
                if (!File.Exists(path))
                {
                    return true;
                }
                if (!RejectUnsafeExisting(path, out error)) return false;
                File.Delete(path);
                if (File.Exists(path))
                {
                    error = "journal_still_present";
                    return false;
                }
                return true;
            }
            catch
            {
                error = "journal_delete_failed";
                return false;
            }
        }

        public static bool RejectUnsafeExisting(string path, out string error)
        {
            error = null;
            if (!File.Exists(path) && !Directory.Exists(path)) return true;
            uint attrs = Native.GetFileAttributes(path);
            if (Native.FileAttrsAreReparse(attrs))
            {
                error = "journal_reparse";
                return false;
            }
            string owner;
            if (!TryGetOwnerSid(path, out owner, out error)) return false;
            if (!Native.OwnerSidTrusted(owner))
            {
                error = "journal_foreign_owner";
                return false;
            }
            return true;
        }

        public static bool TryGetOwnerSid(string path, out string owner, out string error)
        {
            owner = null;
            error = null;
            IntPtr ownerSid = IntPtr.Zero;
            IntPtr group = IntPtr.Zero;
            IntPtr dacl = IntPtr.Zero;
            IntPtr sacl = IntPtr.Zero;
            IntPtr sd = IntPtr.Zero;
            uint st = Native.GetNamedSecurityInfo(
                path,
                WfpConst.SeFileObject,
                WfpConst.OwnerSecurityInformation,
                out ownerSid,
                out group,
                out dacl,
                out sacl,
                out sd);
            try
            {
                if (st != 0)
                {
                    error = "owner_query=0x" + st.ToString("X8");
                    return false;
                }
                if (ownerSid == IntPtr.Zero || !Native.TrySidToString(ownerSid, out owner))
                {
                    error = "owner_sid";
                    return false;
                }
                return true;
            }
            finally
            {
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
            }
        }

        public static void AtomicWrite(string path, string json, bool protectAcl)
        {
            string err;
            if (!DurableWrite(path, json, out err))
            {
                throw new InvalidOperationException(err ?? "journal_write");
            }
        }
    }

    internal static class JournalPathGuard
    {
        public static string FixedJournalDir()
        {
            string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.GetFullPath(Path.Combine(pd, "NMZP", "native-egress-filter", "journal"));
        }

        public static bool PathUnderFixedRoot(string full, string root)
        {
            if (string.IsNullOrEmpty(full) || string.IsNullOrEmpty(root)) return false;
            string f = Path.GetFullPath(full).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (f.Length < r.Length) return false;
            if (!f.StartsWith(r, StringComparison.OrdinalIgnoreCase)) return false;
            if (f.Length == r.Length) return true;
            char c = f[r.Length];
            return c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar;
        }

        public static bool EnsureWritableStore(out string error)
        {
            error = null;
            string pd = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            string nmzp = Path.Combine(pd, "NMZP");
            string leaf = Path.Combine(nmzp, "native-egress-filter");
            string journal = Path.Combine(leaf, "journal");
            if (!CheckExisting(pd, true, out error)) return false;
            if (Directory.Exists(nmzp) || File.Exists(nmzp))
            {
                if (!CheckExisting(nmzp, false, out error)) return false;
            }
            else
            {
                Directory.CreateDirectory(nmzp);
            }
            if (!EnsureLockedDir(leaf, out error)) return false;
            if (!EnsureLockedDir(journal, out error)) return false;
            return true;
        }

        static bool CheckExisting(string path, bool skipOwner, out string error)
        {
            error = null;
            uint attrs = Native.GetFileAttributes(path);
            if (attrs == WfpConst.InvalidFileAttributes)
            {
                error = "journal_path_missing";
                return false;
            }
            if (Native.FileAttrsAreReparse(attrs))
            {
                error = "journal_reparse";
                return false;
            }
            if (skipOwner) return true;
            string owner;
            if (!JournalIo.TryGetOwnerSid(path, out owner, out error)) return false;
            if (!Native.OwnerSidTrusted(owner))
            {
                error = "journal_foreign_owner";
                return false;
            }
            return true;
        }

        static bool EnsureLockedDir(string path, out string error)
        {
            error = null;
            if (Directory.Exists(path) || File.Exists(path))
            {
                return CheckExisting(path, false, out error);
            }
            IntPtr sd = IntPtr.Zero;
            IntPtr saPtr = IntPtr.Zero;
            try
            {
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                    WfpConst.SddlRevision1,
                    out sd,
                    IntPtr.Zero))
                {
                    error = "sddl";
                    return false;
                }
                Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = 0;
                saPtr = Marshal.AllocHGlobal(sa.nLength);
                Marshal.StructureToPtr(sa, saPtr, false);
                if (!Native.CreateDirectory(path, saPtr))
                {
                    error = "create_dir=" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture);
                    return false;
                }
                return CheckExisting(path, false, out error);
            }
            finally
            {
                if (saPtr != IntPtr.Zero) Marshal.FreeHGlobal(saPtr);
                if (sd != IntPtr.Zero) Native.LocalFree(sd);
            }
        }
    }

    internal sealed class ExemptionEntry
    {
        public string Sid;
        public uint Attributes;

        public ExemptionEntry() { }

        public ExemptionEntry(string sid, uint attributes)
        {
            Sid = sid;
            Attributes = attributes;
        }
    }

    internal sealed class ExemptionMergeResult
    {
        public bool Ok;
        public string Error;
        public bool WouldSet;
        public bool AddedOurs;
        public bool RemovedOurs;
        public bool TakeoverRefused;
        public bool BlockFilterDelete;
        public ExemptionEntry[] NextEntries;
        public int ForeignCount;
    }

    internal static class ExemptionLogic
    {
        public static ExemptionEntry[] Copy(IList<ExemptionEntry> src)
        {
            List<ExemptionEntry> list = new List<ExemptionEntry>();
            if (src == null) return list.ToArray();
            for (int i = 0; i < src.Count; i++)
            {
                if (src[i] == null || string.IsNullOrEmpty(src[i].Sid)) continue;
                if (Find(list, src[i].Sid) >= 0) continue;
                list.Add(new ExemptionEntry(src[i].Sid, src[i].Attributes));
            }
            list.Sort(CompareSid);
            return list.ToArray();
        }

        static int CompareSid(ExemptionEntry a, ExemptionEntry b)
        {
            return string.CompareOrdinal(a.Sid, b.Sid);
        }

        public static int Find(IList<ExemptionEntry> list, string sid)
        {
            if (list == null || sid == null) return -1;
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i] != null && string.Equals(list[i].Sid, sid, StringComparison.Ordinal)) return i;
            }
            return -1;
        }

        public static bool Contains(IList<ExemptionEntry> list, string sid)
        {
            return Find(list, sid) >= 0;
        }

        public static string[] Sids(IList<ExemptionEntry> list)
        {
            ExemptionEntry[] c = Copy(list);
            string[] s = new string[c.Length];
            for (int i = 0; i < c.Length; i++) s[i] = c[i].Sid;
            return s;
        }

        public static string[] SortedCopy(IList<string> sids)
        {
            List<string> list = new List<string>();
            if (sids != null)
            {
                for (int i = 0; i < sids.Count; i++)
                {
                    if (!string.IsNullOrEmpty(sids[i]) && !list.Contains(sids[i])) list.Add(sids[i]);
                }
            }
            list.Sort(StringComparer.Ordinal);
            return list.ToArray();
        }

        public static bool Contains(string[] sids, string sid)
        {
            if (sids == null || sid == null) return false;
            for (int i = 0; i < sids.Length; i++)
            {
                if (string.Equals(sids[i], sid, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        static string[] ForeignSids(IList<ExemptionEntry> list, string ourSid)
        {
            List<string> f = new List<string>();
            ExemptionEntry[] c = Copy(list);
            for (int i = 0; i < c.Length; i++)
            {
                if (!string.Equals(c[i].Sid, ourSid, StringComparison.Ordinal)) f.Add(c[i].Sid);
            }
            return f.ToArray();
        }

        static string[] Dropped(string[] before, string[] after)
        {
            List<string> d = new List<string>();
            for (int i = 0; i < before.Length; i++)
            {
                if (!Contains(after, before[i])) d.Add(before[i]);
            }
            return d.ToArray();
        }

        public static ExemptionMergeResult PlanAdd(IList<ExemptionEntry> existing, string ourSid, bool journalOwnsThisSid)
        {
            ExemptionMergeResult r = new ExemptionMergeResult();
            ExemptionEntry[] cur = Copy(existing);
            r.NextEntries = cur;
            r.ForeignCount = ForeignSids(cur, ourSid).Length;
            if (Contains(cur, ourSid))
            {
                if (!journalOwnsThisSid)
                {
                    r.Ok = false;
                    r.TakeoverRefused = true;
                    r.BlockFilterDelete = true;
                    r.Error = "exemption_takeover_refused";
                    return r;
                }
                r.Ok = true;
                r.WouldSet = false;
                return r;
            }
            List<ExemptionEntry> next = new List<ExemptionEntry>(cur);
            next.Add(new ExemptionEntry(ourSid, 0));
            r.Ok = true;
            r.WouldSet = true;
            r.AddedOurs = true;
            r.NextEntries = Copy(next);
            return r;
        }

        public static ExemptionMergeResult PlanRemove(IList<ExemptionEntry> existing, string ourSid, bool weAdded)
        {
            ExemptionMergeResult r = new ExemptionMergeResult();
            ExemptionEntry[] cur = Copy(existing);
            r.NextEntries = cur;
            r.ForeignCount = ForeignSids(cur, ourSid).Length;
            bool present = Contains(cur, ourSid);
            if (present && !weAdded)
            {
                r.Ok = false;
                r.TakeoverRefused = true;
                r.BlockFilterDelete = true;
                r.Error = "exemption_conflict_leave_block";
                return r;
            }
            if (!present)
            {
                r.Ok = true;
                r.WouldSet = false;
                return r;
            }
            List<ExemptionEntry> next = new List<ExemptionEntry>();
            for (int i = 0; i < cur.Length; i++)
            {
                if (!string.Equals(cur[i].Sid, ourSid, StringComparison.Ordinal)) next.Add(cur[i]);
            }
            r.Ok = true;
            r.WouldSet = true;
            r.RemovedOurs = true;
            r.NextEntries = Copy(next);
            return r;
        }

        public static string VerifyAfterAdd(IList<ExemptionEntry> before, IList<ExemptionEntry> after, string ourSid)
        {
            if (!Contains(after, ourSid)) return "reread_missing_ours";
            string[] dropped = Dropped(ForeignSids(before, ourSid), ForeignSids(after, ourSid));
            if (dropped.Length > 0) return "exemption_concurrent_change";
            if (!SameForeignAttributesPreserved(before, after, ourSid)) return "exemption_concurrent_change";
            return null;
        }

        public static string VerifyAfterRemove(IList<ExemptionEntry> before, IList<ExemptionEntry> after, string ourSid)
        {
            if (Contains(after, ourSid)) return "reread_ours_still_present";
            string[] dropped = Dropped(ForeignSids(before, ourSid), ForeignSids(after, ourSid));
            if (dropped.Length > 0) return "exemption_concurrent_change";
            if (!SameForeignAttributesPreserved(before, after, ourSid)) return "exemption_concurrent_change";
            return null;
        }

        public static bool SameEntries(IList<ExemptionEntry> a, IList<ExemptionEntry> b)
        {
            ExemptionEntry[] x = Copy(a);
            ExemptionEntry[] y = Copy(b);
            if (x.Length != y.Length) return false;
            for (int i = 0; i < x.Length; i++)
            {
                if (!string.Equals(x[i].Sid, y[i].Sid, StringComparison.Ordinal)) return false;
                if (x[i].Attributes != y[i].Attributes) return false;
            }
            return true;
        }

        public static bool SameForeignAttributesPreserved(IList<ExemptionEntry> before, IList<ExemptionEntry> next, string ourSid)
        {
            ExemptionEntry[] b = Copy(before);
            ExemptionEntry[] n = Copy(next);
            for (int i = 0; i < b.Length; i++)
            {
                if (string.Equals(b[i].Sid, ourSid, StringComparison.Ordinal)) continue;
                int j = Find(n, b[i].Sid);
                if (j < 0) return false;
                if (n[j].Attributes != b[i].Attributes) return false;
            }
            return true;
        }
    }

    internal sealed class JobScanStats
    {
        public int Matches;
        public int SessionDenied;
        public int SystemDenied;
        public int OtherUnknown;
        public bool EnumTruncated;
        public bool JobMissing;
        public bool JobNotEmpty;
        public uint ActiveProcesses;
        public int PidCount;
        public int BufferSlots;
        public bool JobOwnerKnown;
        public bool JobOwnerTrusted;
        public bool JobBreakawayOk;
        public bool JobSilentBreakawayOk;
        public bool JobKillOnClose;
        public bool JobProcessListComplete;
        public uint JobAssignedProcesses;

        public static JobScanStats TrustedEmpty()
        {
            JobScanStats s = new JobScanStats();
            s.JobOwnerKnown = true;
            s.JobOwnerTrusted = true;
            s.JobProcessListComplete = true;
            s.JobKillOnClose = true;
            return s;
        }

        public int UnreadableCount()
        {
            return SystemDenied + SessionDenied + OtherUnknown;
        }
    }

    internal static class JobProofEval
    {
        public static bool EnumBufferFull(int bytesNeeded, int bufferBytes)
        {
            return bytesNeeded >= bufferBytes;
        }

        public static bool Evaluate(JobScanStats s, out string error)
        {
            error = null;
            if (s == null)
            {
                error = "job_scan_null";
                return false;
            }
            if (s.JobMissing)
            {
                error = "job_open_failed";
                return false;
            }
            if (!s.JobOwnerKnown)
            {
                error = "job_owner_unknown";
                return false;
            }
            if (!s.JobOwnerTrusted)
            {
                error = "job_foreign_owner";
                return false;
            }
            if (s.JobBreakawayOk || s.JobSilentBreakawayOk)
            {
                error = "job_breakaway_allowed";
                return false;
            }
            if (!s.JobProcessListComplete)
            {
                error = "job_pid_list_unknown";
                return false;
            }
            if (s.JobNotEmpty || s.JobAssignedProcesses > 0 || s.ActiveProcesses > 0)
            {
                error = "job_not_empty";
                return false;
            }
            if (s.EnumTruncated)
            {
                error = "enum_processes_truncated";
                return false;
            }
            if (s.Matches > 0)
            {
                error = "package_sid_process_live";
                return false;
            }
            if (s.UnreadableCount() > 0)
            {
                error = "sid_scan_inconclusive";
                return false;
            }
            return true;
        }

        public static bool EvaluateHeld(JobScanStats s, out string error)
        {
            error = null;
            if (s == null)
            {
                error = "job_scan_null";
                return false;
            }
            if (s.JobMissing)
            {
                error = "job_open_failed";
                return false;
            }
            if (!s.JobOwnerKnown)
            {
                error = "job_owner_unknown";
                return false;
            }
            if (!s.JobOwnerTrusted)
            {
                error = "job_foreign_owner";
                return false;
            }
            if (s.JobBreakawayOk || s.JobSilentBreakawayOk)
            {
                error = "job_breakaway_allowed";
                return false;
            }
            if (!s.JobProcessListComplete)
            {
                error = "job_pid_list_unknown";
                return false;
            }
            if (s.JobNotEmpty || s.JobAssignedProcesses > 0 || s.ActiveProcesses > 0)
            {
                error = "job_not_empty";
                return false;
            }
            return true;
        }
    }

    internal static class ResultJson
    {
        public static string Emit(
            bool ok,
            string command,
            bool installed,
            bool verified,
            bool changed,
            string error,
            FilterPlan plan,
            JournalRecord journal,
            Dictionary<string, string> extra)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"ok\":");
            sb.Append(ok ? "true" : "false");
            sb.Append(",\"command\":");
            sb.Append(Json.Escape(command));
            sb.Append(",\"installed\":");
            sb.Append(installed ? "true" : "false");
            sb.Append(",\"verified\":");
            sb.Append(verified ? "true" : "false");
            sb.Append(",\"changed\":");
            sb.Append(changed ? "true" : "false");
            if (error != null)
            {
                sb.Append(",\"error\":");
                sb.Append(Json.Escape(error));
            }
            sb.Append(",\"requiresAdmin\":");
            sb.Append(Native.IsElevatedAdmin() ? "false" : "true");
            if (plan != null)
            {
                sb.Append(",\"journalId\":");
                sb.Append(Json.Escape(plan.JournalId));
                sb.Append(",\"packageSid\":");
                sb.Append(Json.Escape(plan.PackageSid));
                sb.Append(",\"ids\":{\"journalId\":");
                sb.Append(Json.Escape(plan.JournalId));
                sb.Append(",\"providerKey\":");
                sb.Append(Json.Escape(plan.ProviderKey.ToString("D")));
                sb.Append(",\"subLayerKey\":");
                sb.Append(Json.Escape(plan.SubLayerKey.ToString("D")));
                sb.Append(",\"filters\":[");
                for (int i = 0; i < plan.Filters.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(Json.Escape(plan.Filters[i].FilterKey.ToString("D")));
                }
                sb.Append("]}");
            }
            else if (journal != null)
            {
                sb.Append(",\"journalId\":");
                sb.Append(Json.Escape(journal.JournalId));
                sb.Append(",\"state\":");
                sb.Append(Json.Escape(journal.State));
                sb.Append(",\"loopbackExemptionAddedByUs\":");
                sb.Append(journal.LoopbackExemptionAddedByUs ? "true" : "false");
                sb.Append(",\"ids\":{\"journalId\":");
                sb.Append(Json.Escape(journal.JournalId));
                sb.Append(",\"filters\":[");
                for (int i = 0; i < journal.Filters.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(Json.Escape(journal.Filters[i].FilterKey));
                }
                sb.Append("]}");
            }
            if (extra != null)
            {
                foreach (KeyValuePair<string, string> kv in extra)
                {
                    sb.Append(',');
                    sb.Append(Json.Escape(kv.Key));
                    sb.Append(':');
                    if (kv.Value != null && (kv.Value == "true" || kv.Value == "false" || IsInt(kv.Value)))
                    {
                        sb.Append(kv.Value);
                    }
                    else
                    {
                        sb.Append(Json.Escape(kv.Value));
                    }
                }
            }
            sb.Append('}');
            return sb.ToString();
        }

        static bool IsInt(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            int n;
            return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out n)
                && n.ToString(CultureInfo.InvariantCulture) == s;
        }
    }
}
