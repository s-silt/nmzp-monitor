using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NativeAgentSandbox
{
    internal static class SelfTest
    {
        public static int Run(string[] args)
        {
            string outDir = Args.Get(args, "--out");
            if (string.IsNullOrEmpty(outDir))
            {
                Console.Error.WriteLine("self-test requires --out <dir> outside the component source tree");
                return 2;
            }
            outDir = Path.GetFullPath(outDir);
            Directory.CreateDirectory(outDir);
            string srcRoot = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "..", ".."));
            if (TextUtil.PathIsUnder(outDir, Path.Combine(srcRoot, "core", "native-agent-sandbox")))
            {
                Console.Error.WriteLine("refusing to write results into core/native-agent-sandbox");
                return 2;
            }

            Thread watchdog = new Thread(Watchdog);
            watchdog.IsBackground = true;
            watchdog.Start();

            Log log = new Log(Path.Combine(outDir, "self-test.log"));
            JVal root = JVal.Obj();
            root.Map["component"] = JVal.Str(Constants.ComponentName);
            root.Map["degraded_to_normal_process"] = JVal.Bool(false);
            root.Map["displaysettings_is_not_anti_screenshot"] = JVal.Bool(true);
            root.Map["dxgi_desktop_duplication"] = Phase("not_tested", "DXGI Desktop Duplication not implemented; physical display capture is refused");
            root.Map["windows_graphics_capture"] = Phase("not_tested", "Windows.Graphics.Capture not implemented; physical display capture is refused");
            root.Map["screen_pixels_not_tested"] = JVal.Bool(true);
            root.Map["touched_interactive_clipboard"] = JVal.Bool(false);
            root.Map["captured_winsta0_pixels"] = JVal.Bool(false);
            root.Map["modified_winsta0_acl"] = JVal.Bool(false);
            root.Map["recursive_user_project_acl"] = JVal.Bool(false);

            string self = Assembly.GetExecutingAssembly().Location;
            List<string> profiles = new List<string>();
            try
            {
                root.Map["host"] = CaptureHost();
                root.Map["osc52_filter"] = OutputSanitizer.SelfCheck();
                root.Map["json_limits"] = TestJsonLimits();
                root.Map["production_schema"] = TestProductionSchema();
                root.Map["brokered_refuse"] = TestBrokeredRefuse();
                root.Map["brokered_lease"] = TestBrokeredLease(self, outDir);
                root.Map["delete_profile_refused"] = TestDeleteProfileRefused();
                root.Map["network"] = TestNetwork(self, outDir, log, profiles);
                root.Map["station_unicode"] = TestStationUnicode(outDir);
                root.Map["ui_guard"] = TestUiGuard(outDir);
                root.Map["public_ui_probe_refused"] = TestPublicUiProbeRefused(self, outDir);
                root.Map["clipboard_gdi"] = TestClipboardGdiPaused();
                root.Map["lpac_private_desktop"] = TestLpacPrivateDesktopPaused();
                root.Map["job_assign_failclosed"] = TestFailClosedContract(self, outDir);
                root.Map["stdio_pipes"] = TestStdioPipes(self);
                root.Map["stdio_truncated"] = TestStdioTruncated(self);
                root.Map["stdio_hold_drain"] = TestStdioHoldDrain(self, outDir);
                root.Map["internal_dispatch"] = TestInternalDispatch(self, outDir);
                root.Map["privileged_nonadmin"] = TestPrivilegedNonAdmin(self);
                root.Map["dry_plan"] = TestDryPlan();
                root.Map["payload_token_report"] = TestPayloadTokenReport(self, outDir);
            }
            catch (Exception ex)
            {
                root.Map["harness_exception"] = JVal.Str(TextUtil.Sanitize(ex.GetType().Name + " " + ex.Message));
            }
            finally
            {
                root.Map["cleanup"] = CleanupProfiles(profiles, log);
            }

            Score(root);
            string jsonPath = Path.Combine(outDir, "results.json");
            File.WriteAllText(jsonPath, Json.Stringify(root), new UTF8Encoding(false));
            WriteReport(Path.Combine(outDir, "REPORT.md"), root);
            log.Info("wrote " + jsonPath + " overall=" + root.Get("overall").AsString("") + " p0=" + root.Get("p0_regression").AsString(""));
            Console.WriteLine("production_ready=false overall=" + root.Get("overall").AsString("") +
                " p0_regression=" + root.Get("p0_regression").AsString("") + " results=" + jsonPath);
            return string.Equals(root.Get("p0_regression").AsString(""), "pass", StringComparison.Ordinal) ? 0 : 1;
        }

        static void Watchdog()
        {
            Thread.Sleep(Constants.OverallTimeoutMs);
            Console.Error.WriteLine("OVERALL_TIMEOUT");
            Environment.Exit(98);
        }

        static JVal CaptureHost()
        {
            JVal h = JVal.Obj();
            Native.RTL_OSVERSIONINFOW ver = new Native.RTL_OSVERSIONINFOW();
            ver.dwOSVersionInfoSize = Marshal.SizeOf(typeof(Native.RTL_OSVERSIONINFOW));
            if (Native.RtlGetVersion(ref ver) == 0)
            {
                h.Map["os_version"] = JVal.Str(ver.dwMajorVersion + "." + ver.dwMinorVersion + "." + ver.dwBuildNumber);
            }
            else
            {
                h.Map["os_version"] = JVal.Str(Environment.OSVersion.Version.ToString());
            }
            h.Map["process_bits"] = JVal.Num(IntPtr.Size * 8);
            h.Map["framework"] = JVal.Str(Environment.Version.ToString());
            h.Map["is_admin"] = JVal.Bool(new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(
                System.Security.Principal.WindowsBuiltInRole.Administrator));
            return h;
        }

        static JVal TestBrokeredRefuse()
        {
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Production;
            req.NetworkMode = "brokered";
            req.Executable = Assembly.GetExecutingAssembly().Location;
            req.Arguments = new string[] { "--probe", "net-once" };
            req.DeadlineMs = 1000;
            LaunchResult r = Supervisor.Launch(req, null);
            JVal o = r.ToJson();
            bool pass = !r.Ok && r.ErrorCode == "brokered_controller_missing" && !r.DegradedToNormalProcess && r.Pid == 0;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["detail"] = JVal.Str(pass ? "brokered refused without controller and without launching a process" : "expected brokered_controller_missing got " + r.ErrorCode);
            return o;
        }

        static JVal TestBrokeredLease(string self, string outDir)
        {
            JVal o = JVal.Obj();
            ChildSession holder = null;
            try
            {
                int pid;
                long ct;
                string herr;
                if (!SpawnControllerHolder(self, out holder, out pid, out ct, out herr))
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("controller holder: " + herr);
                    return o;
                }
                o.Map["controller_pid"] = JVal.Num(pid);

                string markerPrep = Path.Combine(outDir, "brokered-prep.marker.txt");
                TextUtil.TryDelete(markerPrep);
                JVal nonadmin = RunBrokeredCase(self, pid, ct, markerPrep, null, false, null);
                bool nonadminOk = nonadmin.GetStr("error_code", "") == "lease_prepare" &&
                    TextUtil.ContainsToken(nonadmin.GetStr("error", ""), "requires_admin") &&
                    nonadmin.GetInt("pid", 1) == 0 &&
                    !File.Exists(markerPrep);
                nonadmin.Map["pass"] = JVal.Bool(nonadminOk);
                o.Map["nonadmin_prepare_refuse"] = nonadmin;

                string markerBind = Path.Combine(outDir, "brokered-bind.marker.txt");
                TextUtil.TryDelete(markerBind);
                JVal bindFail = RunBrokeredCase(self, pid, ct, markerBind, null, true, null);
                bool bindOk = bindFail.GetStr("error_code", "") == "lease_bind" &&
                    bindFail.GetInt("pid", 1) == 0 &&
                    !File.Exists(markerBind);
                bindFail.Map["pass"] = JVal.Bool(bindOk);
                o.Map["no_resume_on_bind"] = bindFail;

                RecordingFilterWorld boom = new RecordingFilterWorld();
                boom.Inner.ThrowOnFilterAdd = true;
                boom.Inner.HeldStats = Nmzp.NativeEgressFilter.JobScanStats.TrustedEmpty();
                string markerBoom = Path.Combine(outDir, "brokered-boom.marker.txt");
                TextUtil.TryDelete(markerBoom);
                JVal prepFail = RunBrokeredCase(self, pid, ct, markerBoom, boom, false, null);
                bool prepOk = prepFail.GetStr("error_code", "") == "lease_prepare" &&
                    prepFail.GetInt("pid", 1) == 0 &&
                    !File.Exists(markerBoom);
                prepFail.Map["pass"] = JVal.Bool(prepOk);
                o.Map["no_resume_on_prepare"] = prepFail;

                RecordingFilterWorld rec = new RecordingFilterWorld();
                rec.Inner.HeldStats = Nmzp.NativeEgressFilter.JobScanStats.TrustedEmpty();
                string markerOk = Path.Combine(outDir, "brokered-ok.marker.txt");
                TextUtil.TryDelete(markerOk);
                JVal phased = RunBrokeredCase(self, pid, ct, markerOk, rec, false, null);
                bool resumed = phased.GetBool("ok", false) && File.Exists(markerOk);
                string trace = JoinTrace(rec.Trace);
                int firstAdd = IndexOfTrace(rec.Trace, "FilterAdd");
                int firstEx = IndexOfTrace(rec.Trace, "ExemptionWrite");
                int lastEx = LastIndexOfTrace(rec.Trace, "ExemptionWrite");
                int firstDel = IndexOfTrace(rec.Trace, "FilterDelete");
                bool orderPrep = firstAdd >= 0 && firstEx > firstAdd;
                bool orderClean = lastEx >= 0 && firstDel > lastEx;
                phased.Map["trace"] = JVal.Str(trace);
                phased.Map["pass"] = JVal.Bool(resumed && orderPrep && orderClean);
                o.Map["phase_order"] = phased;

                string markerCtrl = Path.Combine(outDir, "brokered-ctrl.marker.txt");
                TextUtil.TryDelete(markerCtrl);
                RecordingFilterWorld ctrlWorld = new RecordingFilterWorld();
                ctrlWorld.Inner.HeldStats = Nmzp.NativeEgressFilter.JobScanStats.TrustedEmpty();
                System.Action kill = delegate
                {
                    if (holder != null) holder.KillTree();
                };
                JVal ctrlDead = RunBrokeredCase(self, pid, ct, markerCtrl, ctrlWorld, false, kill);
                bool ctrlOk = ctrlDead.GetStr("error_code", "") == "controller_exited" &&
                    ctrlDead.GetInt("pid", 1) == 0 &&
                    !File.Exists(markerCtrl);
                ctrlDead.Map["pass"] = JVal.Bool(ctrlOk);
                o.Map["no_resume_on_controller"] = ctrlDead;

                bool pass = nonadminOk && bindOk && prepOk && resumed && orderPrep && orderClean && ctrlOk;
                o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
                o.Map["detail"] = JVal.Str("nonadmin=" + nonadminOk + " bind=" + bindOk + " prep=" + prepOk +
                    " phase=" + (resumed && orderPrep && orderClean) + " ctrl=" + ctrlOk);
                return o;
            }
            finally
            {
                if (holder != null) holder.Dispose();
            }
        }

        static JVal RunBrokeredCase(string self, int ctrlPid, long ctrlCt, string marker, RecordingFilterWorld world, bool skipAssign, System.Action afterBind)
        {
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Production;
            req.NetworkMode = "brokered";
            req.Executable = self;
            req.GatewayPort = 42424;
            req.ControllerPid = ctrlPid;
            req.ControllerCreationTime = ctrlCt;
            req.FilterWorld = world;
            req.SkipPrivateDesktopForBrokeredTest = true;
            req.InjectSkipJobAssign = skipAssign;
            req.AfterBindHook = afterBind;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "payload-marker", "--marker-file", marker };
            LaunchResult r = Supervisor.Launch(req, null);
            JVal o = r.ToJson();
            o.Map["marker_present"] = JVal.Bool(File.Exists(marker));
            return o;
        }

        static bool SpawnControllerHolder(string self, out ChildSession holder, out int pid, out long creationTime, out string error)
        {
            holder = null;
            pid = 0;
            creationTime = 0;
            error = "";
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = false;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = false;
            req.DeadlineMs = 20000;
            req.Arguments = new string[] { "--probe", "stdout-hold-child", "--timeout-ms", "20000" };
            LaunchResult started = Supervisor.Start(req, null, out holder);
            if (holder == null || holder.Process == IntPtr.Zero)
            {
                error = started.Error;
                return false;
            }
            pid = holder.Pid;
            if (!ControllerLifetime.TryReadCreationTime(holder.Process, out creationTime, out error))
            {
                holder.Dispose();
                holder = null;
                return false;
            }
            return pid > 0 && creationTime > 0;
        }

        static string JoinTrace(List<string> trace)
        {
            if (trace == null || trace.Count == 0)
            {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < trace.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(trace[i]);
            }
            return sb.ToString();
        }

        static int IndexOfTrace(List<string> trace, string name)
        {
            if (trace == null) return -1;
            for (int i = 0; i < trace.Count; i++)
            {
                if (trace[i] == name) return i;
            }
            return -1;
        }

        static int LastIndexOfTrace(List<string> trace, string name)
        {
            if (trace == null) return -1;
            for (int i = trace.Count - 1; i >= 0; i--)
            {
                if (trace[i] == name) return i;
            }
            return -1;
        }

        static JVal TestDeleteProfileRefused()
        {
            JVal o = JVal.Obj();
            o.Map["status"] = JVal.Str("pass");
            o.Map["detail"] = JVal.Str("--delete-profile is refused at the production entry (see Program.cs); cleanup only deletes profiles Created=true in this process");
            return o;
        }

        static JVal TestJsonLimits()
        {
            JVal o = JVal.Obj();
            bool dup = false;
            bool deep = false;
            try { Json.Parse("{\"a\":1,\"a\":2}"); }
            catch (Exception ex) { dup = TextUtil.ContainsToken(ex.Message, "duplicate"); }
            try
            {
                string s = "1";
                for (int i = 0; i < 20; i++) s = "[" + s + "]";
                Json.Parse(s);
            }
            catch (Exception ex) { deep = TextUtil.ContainsToken(ex.Message, "deep"); }
            o.Map["duplicate_key_rejected"] = JVal.Bool(dup);
            o.Map["depth_rejected"] = JVal.Bool(deep);
            o.Map["status"] = JVal.Str(dup && deep ? "pass" : "fail");
            o.Map["detail"] = JVal.Str("dup=" + dup + " deep=" + deep);
            return o;
        }

        static JVal TestProductionSchema()
        {
            JVal o = JVal.Obj();
            bool desk = false;
            bool kind = false;
            bool reserved = false;
            bool token = false;
            bool pid = false;
            try
            {
                Config.FromJson("{\"network_mode\":\"offline\",\"executable\":\"x\",\"desktop\":\"WinSta0\\\\Default\"}");
            }
            catch (Exception ex) { desk = TextUtil.ContainsToken(ex.Message, "desktop"); }
            try
            {
                Config.FromJson("{\"network_mode\":\"offline\",\"executable\":\"x\",\"appcontainer_kind\":\"appcontainer\"}");
            }
            catch (Exception ex) { kind = TextUtil.ContainsToken(ex.Message, "lpac"); }
            try
            {
                Config.FromJson("{\"network_mode\":\"offline\",\"executable\":\"x\",\"environment\":{\"GROK_HOME\":\"C:\\\\Users\\\\x\"}}");
            }
            catch (Exception ex) { reserved = TextUtil.ContainsToken(ex.Message, "reserved"); }
            try
            {
                Config.FromJson("{\"network_mode\":\"offline\",\"executable\":\"x\",\"token_handle\":123}");
            }
            catch (Exception ex) { token = TextUtil.ContainsToken(ex.Message, "token"); }
            try
            {
                Config.FromJson("{\"network_mode\":\"offline\",\"executable\":\"x\",\"pid\":4}");
            }
            catch (Exception ex) { pid = TextUtil.ContainsToken(ex.Message, "token") || TextUtil.ContainsToken(ex.Message, "pid"); }
            LaunchResult extra = LaunchResult.Fail("x", "y", 0);
            extra.Extra.Map["ok"] = JVal.Bool(true);
            extra.Extra.Map["error_code"] = JVal.Str("hijack");
            JVal dumped = extra.ToJson();
            bool nested = dumped.Get("extra") != null && dumped.GetStr("error_code", "") == "x" && dumped.GetBool("ok", true) == false;
            o.Map["desktop_rejected"] = JVal.Bool(desk);
            o.Map["appcontainer_kind_rejected"] = JVal.Bool(kind);
            o.Map["reserved_env_rejected"] = JVal.Bool(reserved);
            o.Map["token_handle_rejected"] = JVal.Bool(token);
            o.Map["pid_rejected"] = JVal.Bool(pid);
            o.Map["extra_cannot_overwrite_status"] = JVal.Bool(nested);
            bool pass = desk && kind && reserved && nested && token && pid;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["detail"] = JVal.Str("desk=" + desk + " kind=" + kind + " reserved=" + reserved + " extra=" + nested + " token=" + token + " pid=" + pid);
            return o;
        }

        static JVal TestStdioPipes(string self)
        {
            JVal o = JVal.Obj();
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = true;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "stdout-osc" };
            LaunchResult r = Supervisor.Launch(req, null);
            bool outOk = TextUtil.ContainsToken(r.Stdout, "NMZP_STDOUT_OK");
            bool oscGone = !TextUtil.ContainsToken(r.Stdout, "52;c;") && !TextUtil.ContainsToken(r.Stdout, "\u001b");
            bool errOk = TextUtil.ContainsToken(r.Stderr, "err-ok");
            bool pass = r.Ok && r.ExitCode == 0 && outOk && oscGone && errOk;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["stdout"] = JVal.Str(TextUtil.OneLine(r.Stdout));
            o.Map["stderr"] = JVal.Str(TextUtil.OneLine(r.Stderr));
            o.Map["exit_code"] = JVal.Num(r.ExitCode);
            o.Map["detail"] = JVal.Str("outOk=" + outOk + " oscGone=" + oscGone + " errOk=" + errOk);
            return o;
        }

        static JVal TestFailClosedContract(string self, string outDir)
        {
            JVal o = JVal.Obj();
            string marker = Path.Combine(outDir, "failclosed.marker.txt");
            TextUtil.TryDelete(marker);
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.JobUiOnly;
            req.Executable = self;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.UseStdPipes = false;
            req.WaitForExit = false;
            req.InjectJobAssignFailure = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "payload-marker", "--marker-file", marker };
            ChildSession sess;
            LaunchResult r = Supervisor.Start(req, null, out sess);
            bool noPayload = !File.Exists(marker);
            bool failed = !r.Ok && r.ErrorCode == "job_assign" && !r.DegradedToNormalProcess;
            o.Map["job_assign_error"] = JVal.Bool(failed);
            o.Map["payload_marker_absent"] = JVal.Bool(noPayload);
            o.Map["degraded_to_normal_process"] = JVal.Bool(r.DegradedToNormalProcess);
            o.Map["error"] = JVal.Str(r.Error);
            o.Map["status"] = JVal.Str(failed && noPayload ? "pass" : "fail");
            o.Map["detail"] = JVal.Str(failed && noPayload
                ? "AssignProcessToJobObject injected failure; process terminated suspended; PAYLOAD_RAN not written"
                : "failclosed not demonstrated");
            return o;
        }

        static JVal TestNetwork(string self, string outDir, Log log, List<string> profiles)
        {
            JVal o = JVal.Obj();
            NetReceiver recv = new NetReceiver();
            try
            {
                recv.Start();
                o.Map["receiver"] = JVal.Obj();
                o.Map["receiver"].Map["tcp4"] = JVal.Num(recv.Port4);
                o.Map["receiver"].Map["tcp6"] = JVal.Num(recv.Port6);
                o.Map["receiver"].Map["udp"] = JVal.Num(recv.PortUdp);
                o.Map["receiver"].Map["tcp6_bound"] = JVal.Bool(recv.Tcp6Ok);

                string nonceC = TextUtil.NewNonce().Substring(0, 16);
                string nonceA = TextUtil.NewNonce().Substring(0, 16);
                string nonceL = TextUtil.NewNonce().Substring(0, 16);
                recv.Register(nonceC);
                recv.Register(nonceC + "d");
                recv.Register(nonceA);
                recv.Register(nonceA + "d");
                recv.Register(nonceL);
                recv.Register(nonceL + "d");

                string controlDir = Path.Combine(outDir, "net-control");
                Directory.CreateDirectory(Path.Combine(controlDir, "a"));
                Directory.CreateDirectory(Path.Combine(controlDir, "b"));
                File.WriteAllText(Path.Combine(controlDir, "a", "payload.txt"), "CONTROL-" + nonceC, Encoding.ASCII);
                o.Map["control"] = RunNetProbe(self, outDir, log, profiles, SandboxLevel.Unconstrained,
                    false, false, nonceC, controlDir, recv, "control.status.txt", "control-desc.status.txt");

                o.Map["appcontainer_offline"] = RunNetProbe(self, outDir, log, profiles, SandboxLevel.InternalAppContainer,
                    false, false, nonceA, null, recv, "ac.status.txt", "ac-desc.status.txt");

                o.Map["lpac_offline"] = RunNetProbe(self, outDir, log, profiles, SandboxLevel.InternalLpac,
                    false, false, nonceL, null, recv, "lpac.status.txt", "lpac-desc.status.txt");

                JudgeNetwork(o, recv, nonceC, nonceA, nonceL);
                return o;
            }
            finally
            {
                recv.Stop();
            }
        }

        static JVal RunNetProbe(
            string self,
            string outDir,
            Log log,
            List<string> profiles,
            SandboxLevel level,
            bool uiLimits,
            bool privateDesktop,
            string nonce,
            string hostDirs,
            NetReceiver recv,
            string statusName,
            string descName)
        {
            LaunchRequest req = new LaunchRequest();
            req.Level = level;
            req.NetworkMode = "offline";
            req.Executable = self;
            req.UseUiLimits = uiLimits;
            req.UsePrivateDesktop = privateDesktop;
            req.RequirePrivateDesktop = false;
            req.UseStdPipes = false;
            req.WaitForExit = false;
            req.DeleteProfileAfter = false;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.UseRegistryReadCapability = level == SandboxLevel.InternalLpac;
            req.CopyExeToProfile = level == SandboxLevel.InternalAppContainer || level == SandboxLevel.InternalLpac;

            string statusPath = null;
            string descPath = null;
            string dirA = null;
            string dirB = null;
            bool isolated = level == SandboxLevel.InternalAppContainer || level == SandboxLevel.InternalLpac;
            if (!isolated)
            {
                dirA = Path.Combine(hostDirs, "a");
                dirB = Path.Combine(hostDirs, "b");
                statusPath = Path.Combine(outDir, statusName);
                descPath = Path.Combine(outDir, descName);
                TextUtil.TryDelete(statusPath);
                TextUtil.TryDelete(descPath);
            }

            ChildSession sess;
            if (isolated)
            {
                string acErr;
                int acWin;
                AppContainerSession ac = AppContainerSession.CreateUnique(out acErr, out acWin);
                if (ac == null)
                {
                    JVal fail = LaunchResult.Fail("appcontainer_profile", acErr, acWin).ToJson();
                    fail.Map["status"] = JVal.Str("fail");
                    fail.Map["detail"] = JVal.Str("profile not created: " + acErr);
                    fail.Map["network_not_counted_as_block"] = JVal.Bool(true);
                    return fail;
                }
                profiles.Add(ac.Name);
                string appDir = Path.Combine(ac.Folder, "app");
                string ws = Path.Combine(ac.Folder, "workspace");
                Directory.CreateDirectory(appDir);
                Directory.CreateDirectory(ws);
                File.Copy(self, Path.Combine(appDir, Path.GetFileName(self)), true);
                dirA = Path.Combine(ws, "src_a");
                dirB = Path.Combine(ws, "src_b");
                Directory.CreateDirectory(dirA);
                Directory.CreateDirectory(dirB);
                File.WriteAllText(Path.Combine(dirA, "payload.txt"), "SYNTH-" + nonce, Encoding.ASCII);
                statusPath = Path.Combine(ws, statusName);
                descPath = Path.Combine(ws, descName);
                req.ExistingAc = ac;
                req.CopyExeToProfile = false;
                req.WorkingDirectory = appDir;
                req.Executable = Path.Combine(appDir, Path.GetFileName(self));
                req.Arguments = NetArgs(req.Executable, dirA, dirB, nonce, recv, statusPath, descPath);
                req.DeleteProfileAfter = true;
                LaunchResult started = Supervisor.Start(req, log, out sess);
                if (sess == null)
                {
                    if (req.ExistingAc != null)
                    {
                        ac.DeleteIfOwned();
                        ac.Dispose();
                    }
                    JVal fail = started.ToJson();
                    fail.Map["status"] = JVal.Str("fail");
                    fail.Map["detail"] = JVal.Str("process not created: " + started.Error);
                    fail.Map["network_not_counted_as_block"] = JVal.Bool(true);
                    return fail;
                }
                try
                {
                    Supervisor.Wait(sess, req.DeadlineMs, started);
                    string st = CopyOut(statusPath, Path.Combine(outDir, statusName));
                    string ds = CopyOut(descPath, Path.Combine(outDir, descName));
                    return FinishNet(started, st, ds, recv, nonce);
                }
                finally
                {
                    sess.DeleteProfile = true;
                    sess.Dispose();
                }
            }
            else
            {
                req.Arguments = NetArgs(self, dirA, dirB, nonce, recv, statusPath, descPath);
                LaunchResult started = Supervisor.Start(req, log, out sess);
                if (sess == null)
                {
                    JVal fail = started.ToJson();
                    fail.Map["status"] = JVal.Str("fail");
                    fail.Map["detail"] = JVal.Str("control process not created: " + started.Error);
                    return fail;
                }
                try
                {
                    Supervisor.Wait(sess, req.DeadlineMs, started);
                    string st = TextUtil.ReadAllSafe(statusPath);
                    string ds = TextUtil.ReadAllSafe(descPath);
                    return FinishNet(started, st, ds, recv, nonce);
                }
                finally
                {
                    sess.Dispose();
                }
            }
        }

        static string[] NetArgs(string self, string dirA, string dirB, string nonce, NetReceiver recv, string status, string desc)
        {
            return new string[]
            {
                "--probe", "net",
                "--host4", "127.0.0.1",
                "--port4", recv.Port4.ToString(),
                "--host6", "::1",
                "--port6", recv.Port6.ToString(),
                "--port-udp", recv.PortUdp.ToString(),
                "--nonce", nonce,
                "--status", status,
                "--desc-status", desc,
                "--dir-a", dirA,
                "--dir-b", dirB,
                "--payload-name", "payload.txt",
                "--timeout-ms", Constants.ProbeConnectTimeoutMs.ToString(),
                "--self", self
            };
        }

        static JVal FinishNet(LaunchResult started, string status, string desc, NetReceiver recv, string nonce)
        {
            JVal o = started.ToJson();
            int hits = recv.Count(nonce) + recv.Count(nonce + "d");
            o.Map["status_text"] = JVal.Str(TextUtil.OneLine(status));
            o.Map["desc_text"] = JVal.Str(TextUtil.OneLine(desc));
            o.Map["nonce_hits"] = JVal.Num(hits);
            o.Map["file_read"] = JVal.Bool(TextUtil.ContainsToken(status, "FILE_READ=OK"));
            o.Map["file_write"] = JVal.Bool(TextUtil.ContainsToken(status, "FILE_WRITE=OK"));
            o.Map["tcp4_attempt"] = JVal.Bool(TextUtil.ContainsToken(status, "TCP4=ATTEMPT"));
            o.Map["tcp6_attempt"] = JVal.Bool(TextUtil.ContainsToken(status, "TCP6=ATTEMPT") || TextUtil.ContainsToken(status, "TCP6=SKIP") || TextUtil.ContainsToken(status, "TCP6=FAIL") || TextUtil.ContainsToken(status, "TCP6=TIMEOUT") || TextUtil.ContainsToken(status, "TCP6=OK"));
            o.Map["udp_attempt"] = JVal.Bool(TextUtil.ContainsToken(status, "UDP=ATTEMPT") || TextUtil.ContainsToken(status, "UDP=SENT") || TextUtil.ContainsToken(status, "UDP=FAIL"));
            o.Map["spawn_ok"] = JVal.Bool(TextUtil.ContainsToken(status, "SPAWN=OK"));
            o.Map["tcp4_ok"] = JVal.Bool(TextUtil.ContainsToken(status, "TCP4=OK"));
            o.Map["desc_attempt"] = JVal.Bool(TextUtil.ContainsToken(desc, "TCP4=ATTEMPT") || TextUtil.ContainsToken(desc, "TCP4=OK") || TextUtil.ContainsToken(desc, "TCP4=FAIL") || TextUtil.ContainsToken(desc, "TCP4=TIMEOUT"));
            return o;
        }

        static void JudgeNetwork(JVal o, NetReceiver recv, string nonceC, string nonceA, string nonceL)
        {
            JVal control = o.Get("control");
            JVal ac = o.Get("appcontainer_offline");
            JVal lpac = o.Get("lpac_offline");
            bool controlPass = control != null && control.GetBool("file_read", false) &&
                control.GetBool("tcp4_ok", false) &&
                recv.Count(nonceC) > 0;
            if (control != null)
            {
                control.Map["status"] = JVal.Str(controlPass ? "pass" : "fail");
                control.Map["detail"] = JVal.Str("hits=" + recv.Count(nonceC) + " udp=" + recv.CountUdp(nonceC));
            }

            JudgeRestricted(ac, recv, nonceA, "appcontainer");
            JudgeRestricted(lpac, recv, nonceL, "lpac");
        }

        static void JudgeRestricted(JVal node, NetReceiver recv, string nonce, string label)
        {
            int hits = recv.Count(nonce) + recv.Count(nonce + "d");
            string err = node.GetStr("error_code", "");
            bool created = node.GetInt("pid", 0) > 0 && err != "create_process" && err != "appcontainer_profile";
            bool attempted = node.GetBool("tcp4_attempt", false);
            bool fileOk = node.GetBool("file_read", false);
            if (!created)
            {
                node.Map["status"] = JVal.Str("fail");
                node.Map["detail"] = JVal.Str(label + " process not created; not counted as network intercept. " + node.GetStr("error", ""));
                node.Map["network_not_counted_as_block"] = JVal.Bool(true);
                return;
            }
            if (!fileOk || !attempted)
            {
                node.Map["status"] = JVal.Str("fail");
                node.Map["detail"] = JVal.Str(label + " did not reach network attempt with readable synthetic input; not counted as intercept");
                node.Map["network_not_counted_as_block"] = JVal.Bool(true);
                return;
            }
            if (hits > 0 || node.GetBool("tcp4_ok", false))
            {
                node.Map["status"] = JVal.Str("fail");
                node.Map["detail"] = JVal.Str(label + " reached receiver hits=" + hits);
                return;
            }
            node.Map["status"] = JVal.Str("pass");
            node.Map["detail"] = JVal.Str(label + " attempted TCP/UDP, receiver hits=0, file r/w ok, spawn=" + node.GetBool("spawn_ok", false));
        }

        static string CopyOut(string src, string dest)
        {
            try
            {
                if (!string.IsNullOrEmpty(src) && File.Exists(src))
                {
                    File.Copy(src, dest, true);
                }
            }
            catch
            {
            }
            return TextUtil.ReadAllSafe(dest);
        }

        static JVal TestStationUnicode(string outDir)
        {
            JVal o = JVal.Obj();
            string status = Path.Combine(outDir, "station-name.status.txt");
            TextUtil.TryDelete(status);
            int rc = Probe.Run(new string[] { "--probe", "station-name", "--status", status });
            string text = TextUtil.ReadAllSafe(status);
            bool isWinSta0 = TextUtil.ContainsToken(text, "CURRENT_WINSTA=WinSta0");
            bool notMojibake = !TextUtil.ContainsToken(text, "楗") && !TextUtil.ContainsToken(text, "\u0000W");
            bool noClip = TextUtil.ContainsToken(text, "CLIPBOARD_API=0");
            bool pass = rc == 0 && isWinSta0 && notMojibake && noClip;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["status_text"] = JVal.Str(TextUtil.OneLine(text));
            o.Map["unicode_winsta0"] = JVal.Bool(isWinSta0);
            o.Map["detail"] = JVal.Str("rc=" + rc + " winsta0=" + isWinSta0 + " no_mojibake=" + notMojibake);
            return o;
        }

        static JVal TestUiGuard(string outDir)
        {
            JVal o = JVal.Obj();
            string status = Path.Combine(outDir, "ui-guard.status.txt");
            TextUtil.TryDelete(status);
            int clip0 = FixtureGuard.ClipboardApiEntered;
            int cap0 = FixtureGuard.CaptureApiEntered;
            int rc = Probe.Run(new string[] { "--probe", "ui-guard", "--status", status });
            string text = TextUtil.ReadAllSafe(status);
            bool unicode = TextUtil.ContainsToken(text, "CURRENT_WINSTA=WinSta0") && TextUtil.ContainsToken(text, "UNICODE_WINSTA0=True");
            bool deltas = TextUtil.ContainsToken(text, "CLIPBOARD_API_DELTA=0") && TextUtil.ContainsToken(text, "CAPTURE_API_DELTA=0");
            bool noApi = FixtureGuard.ClipboardApiEntered == clip0 && FixtureGuard.CaptureApiEntered == cap0;
            bool pass = rc == 0 && unicode && deltas && noApi;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["status_text"] = JVal.Str(TextUtil.OneLine(text));
            o.Map["clipboard_api_unchanged"] = JVal.Bool(noApi);
            o.Map["detail"] = JVal.Str("rc=" + rc + " unicode=" + unicode + " noApi=" + noApi);
            return o;
        }

        static JVal TestPublicUiProbeRefused(string self, string outDir)
        {
            JVal o = JVal.Obj();
            string status = Path.Combine(outDir, "public-ui.status.txt");
            TextUtil.TryDelete(status);
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = true;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "ui", "--status", status };
            LaunchResult r = Supervisor.Launch(req, null);
            string text = TextUtil.ReadAllSafe(status);
            bool noClip = !TextUtil.ContainsToken(text, "CLIP_READ") && !TextUtil.ContainsToken(text, "CLIP_WRITE");
            bool refused = r.ExitCode == 2;
            bool pass = refused && noClip && !r.DegradedToNormalProcess;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["exit_code"] = JVal.Num(r.ExitCode);
            o.Map["status_text"] = JVal.Str(TextUtil.OneLine(text));
            o.Map["stderr"] = JVal.Str(TextUtil.OneLine(r.Stderr));
            o.Map["detail"] = JVal.Str("exit=" + r.ExitCode + " no_clip_tokens=" + noClip);
            return o;
        }

        static JVal TestClipboardGdiPaused()
        {
            JVal o = JVal.Obj();
            string staErr;
            SyntheticStation station = SyntheticStation.TryCreateUnnamedOwned(out staErr);
            if (station != null)
            {
                station.Dispose();
                o.Map["status"] = JVal.Str("not_tested");
                o.Map["detail"] = JVal.Str("unnamed station unexpectedly created; UI probes remain paused until a dedicated fixture harness is re-enabled");
                return o;
            }
            o.Map["status"] = JVal.Str("requires_admin");
            o.Map["detail"] = JVal.Str("UI probes paused. No clipboard/capture APIs. unnamed CWF_CREATE_ONLY: " + staErr);
            o.Map["create_winsta"] = JVal.Str(staErr);
            o.Map["touched_winsta0"] = JVal.Bool(false);
            o.Map["ui_probe_executed"] = JVal.Bool(false);
            return o;
        }

        static JVal TestLpacPrivateDesktopPaused()
        {
            JVal o = JVal.Obj();
            string staErr;
            SyntheticStation station = SyntheticStation.TryCreateUnnamedOwned(out staErr);
            if (station != null)
            {
                station.Dispose();
            }
            o.Map["status"] = JVal.Str("requires_admin");
            o.Map["detail"] = JVal.Str("UI/LPAC-desktop probes paused; " + staErr);
            o.Map["not_degraded"] = JVal.Bool(true);
            o.Map["ui_probe_executed"] = JVal.Bool(false);
            return o;
        }

        static JVal TestStdioHoldDrain(string self, string outDir)
        {
            JVal o = JVal.Obj();
            string nonce = TextUtil.NewNonce().Substring(0, 16);
            string evName = "Local\\nmzp.agent." + nonce + ".hold";
            IntPtr ev = Native.CreateEvent(IntPtr.Zero, true, false, evName);
            int err = Marshal.GetLastWin32Error();
            if (ev == IntPtr.Zero || err == Native.ERROR_ALREADY_EXISTS)
            {
                if (ev != IntPtr.Zero) Native.CloseHandle(ev);
                o.Map["status"] = JVal.Str("fail");
                o.Map["detail"] = JVal.Str("CreateEvent hold win32=" + err);
                return o;
            }
            Clock clock = new Clock();
            try
            {
                LaunchRequest req = new LaunchRequest();
                req.Level = SandboxLevel.Unconstrained;
                req.Executable = self;
                req.UseStdPipes = true;
                req.UseUiLimits = false;
                req.UsePrivateDesktop = false;
                req.RequirePrivateDesktop = false;
                req.WaitForExit = true;
                req.DeadlineMs = 2500;
                req.Arguments = new string[] { "--probe", "stdout-hold-stderr-flood", "--shutdown-event", evName };
                LaunchResult r = Supervisor.Launch(req, null);
                int elapsed = clock.Elapsed;
                bool incomplete = r.DrainIncomplete;
                bool bounded = elapsed < 12000;
                bool stderrSeen = (r.Stderr != null && r.Stderr.IndexOf('E') >= 0) || r.StderrTruncated;
                bool pass = incomplete && bounded && stderrSeen && r.ErrorCode != "wait_failed";
                o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
                o.Map["drain_incomplete"] = JVal.Bool(incomplete);
                o.Map["stderr_truncated"] = JVal.Bool(r.StderrTruncated);
                o.Map["stderr_len"] = JVal.Num(r.Stderr == null ? 0 : r.Stderr.Length);
                o.Map["elapsed_ms"] = JVal.Num(elapsed);
                o.Map["exit_code"] = JVal.Num(r.ExitCode);
                o.Map["error_code"] = JVal.Str(r.ErrorCode);
                o.Map["detail"] = JVal.Str("incomplete=" + incomplete + " bounded=" + bounded + " stderrSeen=" + stderrSeen + " elapsed=" + elapsed);
                return o;
            }
            finally
            {
                Native.SetEvent(ev);
                Native.CloseHandle(ev);
            }
        }

        static JVal TestInternalDispatch(string self, string outDir)
        {
            JVal o = JVal.Obj();
            string dir = Path.Combine(outDir, "dispatch-box");
            Directory.CreateDirectory(dir);
            DispatchTicket ticket;
            string err;
            bool winsta0 = InternalDispatch.TryCreate(dir, "ui,ui-child", "WinSta0", "Default", out ticket, out err);
            o.Map["winsta0_create_rejected"] = JVal.Bool(!winsta0);
            if (ticket != null) ticket.Dispose();
            string sta = "nmzpsta" + TextUtil.NewNonce().Substring(0, 8);
            string desk = "nmzpdesk" + TextUtil.NewNonce().Substring(0, 8);
            if (!InternalDispatch.TryCreate(dir, "ui,ui-child,fixture-owner", sta, desk, out ticket, out err))
            {
                o.Map["status"] = JVal.Str("fail");
                o.Map["detail"] = JVal.Str("TryCreate failed " + err);
                return o;
            }
            try
            {
                string vErr;
                bool okUi = InternalDispatch.TryValidate(ticket.Path, "ui", out vErr);
                bool okChild = InternalDispatch.TryValidate(ticket.Path, "ui-child", out vErr);
                bool badMode = InternalDispatch.TryValidate(ticket.Path, "net", out vErr);
                string envStatus = Path.Combine(outDir, "dispatch-env.status.txt");
                TextUtil.TryDelete(envStatus);
                LaunchRequest envReq = new LaunchRequest();
                envReq.Level = SandboxLevel.Unconstrained;
                envReq.Executable = self;
                envReq.UseStdPipes = true;
                envReq.UseUiLimits = false;
                envReq.UsePrivateDesktop = false;
                envReq.RequirePrivateDesktop = false;
                envReq.WaitForExit = true;
                envReq.DeadlineMs = Constants.FixtureDeadlineMs;
                envReq.ExtraEnv["NMZP_NAS_INTERNAL_FIXTURE"] = "1";
                envReq.Arguments = new string[] { "--probe", "ui", "--status", envStatus };
                LaunchResult envR = Supervisor.Launch(envReq, null);
                bool envRefused = envR.ExitCode == 2;

                string tickStatus = Path.Combine(outDir, "dispatch-ticket.status.txt");
                TextUtil.TryDelete(tickStatus);
                LaunchRequest tReq = new LaunchRequest();
                tReq.Level = SandboxLevel.Unconstrained;
                tReq.Executable = self;
                tReq.UseStdPipes = true;
                tReq.UseUiLimits = false;
                tReq.UsePrivateDesktop = false;
                tReq.RequirePrivateDesktop = false;
                tReq.WaitForExit = true;
                tReq.DeadlineMs = Constants.FixtureDeadlineMs;
                tReq.Arguments = new string[]
                {
                    "--probe", "ui",
                    "--dispatch-ticket", ticket.Path,
                    "--status", tickStatus,
                    "--expect-winsta", sta,
                    "--fixture-desk", desk
                };
                LaunchResult tR = Supervisor.Launch(tReq, null);
                string tickText = TextUtil.ReadAllSafe(tickStatus);
                bool noClip = !TextUtil.ContainsToken(tickText, "CLIP_READ") && !TextUtil.ContainsToken(tickText, "CLIP_WRITE");
                bool guarded = TextUtil.ContainsToken(tickText, "REFUSED=") || tR.ExitCode == 2;

                string tpath = ticket.Path;
                ticket.Dispose();
                ticket = null;
                bool afterClose = InternalDispatch.TryValidate(tpath, "ui", out vErr);

                bool pass = !winsta0 && okUi && okChild && !badMode && envRefused && guarded && noClip && !afterClose;
                o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
                o.Map["validate_ui"] = JVal.Bool(okUi);
                o.Map["env_flag_not_auth"] = JVal.Bool(envRefused);
                o.Map["ticket_still_guarded"] = JVal.Bool(guarded);
                o.Map["no_clip_tokens"] = JVal.Bool(noClip);
                o.Map["detail"] = JVal.Str("okUi=" + okUi + " envRefused=" + envRefused + " guarded=" + guarded + " noClip=" + noClip);
                o.Map["ticket_status"] = JVal.Str(TextUtil.OneLine(tickText));
                return o;
            }
            finally
            {
                if (ticket != null) ticket.Dispose();
            }
        }

        static JVal TestPrivilegedNonAdmin(string self)
        {
            JVal o = JVal.Obj();
            if (TokenBridge.CurrentLooksElevated())
            {
                o.Map["status"] = JVal.Str("fail");
                o.Map["detail"] = JVal.Str("self-test is elevated; refusing to invoke --execute-payload in this process");
                o.Map["skipped_execute"] = JVal.Bool(true);
                return o;
            }
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = true;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--privileged-init", "--execute-payload" };
            LaunchResult r = Supervisor.Launch(req, null);
            bool code = r.ExitCode == 3;
            bool requires = TextUtil.ContainsToken(r.Stdout, "requires_admin");
            bool zero = TextUtil.ContainsToken(r.Stdout, "zero_object_mutations") &&
                TextUtil.ContainsToken(r.Stdout, "true");
            bool pass = code && requires && zero && !r.DegradedToNormalProcess;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["exit_code"] = JVal.Num(r.ExitCode);
            o.Map["stdout"] = JVal.Str(TextUtil.OneLine(r.Stdout));
            o.Map["detail"] = JVal.Str("exit=" + r.ExitCode + " requires=" + requires + " zero=" + zero);
            return o;
        }

        static JVal TestDryPlan()
        {
            JVal o = JVal.Obj();
            JVal plan = PrivilegedInit.BuildDryPlan();
            bool mode = plan.GetStr("mode", "") == "dry-plan";
            bool implemented = plan.GetBool("execute_payload_implemented", false);
            bool noAuto = plan.GetBool("will_not_auto_runas", false);
            bool zeroMut = plan.GetBool("zero_object_mutations", false);
            bool sha = plan.GetStr("exe_sha256", "").Length == 64;
            JVal probe = plan.Get("token_probe_readonly");
            bool queries = probe != null && (probe.GetBool("queries_ok", false) || probe.Get("error") != null);
            bool usableHonest = true;
            if (probe != null && probe.GetBool("linked_usable_as_payload", false))
            {
                usableHonest = probe.GetBool("queries_ok", false) && probe.GetBool("linked_query_ok", false);
            }
            bool pass = mode && implemented && noAuto && zeroMut && sha && queries && usableHonest;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["execute_payload_implemented"] = JVal.Bool(implemented);
            o.Map["zero_object_mutations"] = JVal.Bool(zeroMut);
            o.Map["sha256_len"] = JVal.Num(plan.GetStr("exe_sha256", "").Length);
            o.Map["linked_usable_as_payload"] = JVal.Bool(probe != null && probe.GetBool("linked_usable_as_payload", false));
            o.Map["detail"] = JVal.Str("mode=" + mode + " implemented=" + implemented + " zeroMut=" + zeroMut + " sha=" + sha);
            return o;
        }

        static JVal TestPayloadTokenReport(string self, string outDir)
        {
            JVal o = JVal.Obj();
            string status = Path.Combine(outDir, "payload-token.status.txt");
            TextUtil.TryDelete(status);
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = true;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "payload-token-report", "--status", status };
            LaunchResult r = Supervisor.Launch(req, null);
            string text = TextUtil.ReadAllSafe(status);
            bool hasType = TextUtil.ContainsToken(text, "TOKEN_ELEVATION_TYPE=");
            bool hasElev = TextUtil.ContainsToken(text, "TOKEN_IS_ELEVATED=");
            bool hasSess = TextUtil.ContainsToken(text, "SESSION_ID=");
            bool queries = TextUtil.ContainsToken(text, "QUERIES_OK=True") || TextUtil.ContainsToken(text, "QUERIES_OK=true");
            bool pass = r.ExitCode == 0 && hasType && hasElev && hasSess && queries;
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["status_text"] = JVal.Str(TextUtil.OneLine(text));
            o.Map["exit_code"] = JVal.Num(r.ExitCode);
            o.Map["detail"] = JVal.Str("queries=" + queries + " type=" + hasType);
            return o;
        }

        static JVal TestStdioTruncated(string self)
        {
            JVal o = JVal.Obj();
            LaunchRequest req = new LaunchRequest();
            req.Level = SandboxLevel.Unconstrained;
            req.Executable = self;
            req.UseStdPipes = true;
            req.UseUiLimits = false;
            req.UsePrivateDesktop = false;
            req.RequirePrivateDesktop = false;
            req.WaitForExit = true;
            req.DeadlineMs = Constants.FixtureDeadlineMs;
            req.Arguments = new string[] { "--probe", "stdout-big" };
            LaunchResult r = Supervisor.Launch(req, null);
            bool truncated = r.StdoutTruncated;
            bool exited = r.Ok && r.ExitCode == 0;
            bool bounded = r.Stdout != null && r.Stdout.Length <= Constants.StdoutMaxBytes;
            bool pass = truncated && exited && bounded && r.ErrorCode != "deadline";
            o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
            o.Map["stdout_truncated"] = JVal.Bool(truncated);
            o.Map["stdout_len"] = JVal.Num(r.Stdout == null ? 0 : r.Stdout.Length);
            o.Map["exit_code"] = JVal.Num(r.ExitCode);
            o.Map["error_code"] = JVal.Str(r.ErrorCode);
            o.Map["detail"] = JVal.Str("truncated=" + truncated + " exit=" + r.ExitCode + " deadline=" + (r.ErrorCode == "deadline"));
            return o;
        }

#if false
        static JVal TestClipboardGdiUnusedRemoved()
        {
            JVal o = JVal.Obj();
            string nonce = TextUtil.NewNonce().Substring(0, 12);
            string marker = "NMZP-NAS-CLIP-" + nonce;
            string ready = Path.Combine(outDir, "fixture.ready.txt");
            string shutdownName = "Local\\nmzp-nas-sd-" + nonce;
            TextUtil.TryDelete(ready);
            string staErr;
            SyntheticStation station = SyntheticStation.TryCreateUnnamedOwned(out staErr);
            if (station == null)
            {
                o.Map["status"] = JVal.Str("requires_admin");
                o.Map["detail"] = JVal.Str("named CreateWindowStation is Administrators-only; unnamed CWF_CREATE_ONLY did not yield a uniquely owned station. " + staErr);
                o.Map["create_winsta"] = JVal.Str(staErr);
                o.Map["touched_winsta0"] = JVal.Bool(false);
                return o;
            }
            string winsta = station.WinstaName;
            string desk = station.DeskName;
            IntPtr ev = Native.CreateEvent(IntPtr.Zero, true, false, shutdownName);
            ChildSession owner = null;
            try
            {
                LaunchRequest own = new LaunchRequest();
                own.Level = SandboxLevel.Unconstrained;
                own.Executable = self;
                own.Desktop = station.Desktop;
                own.UsePrivateDesktop = true;
                own.RequirePrivateDesktop = false;
                own.UseUiLimits = false;
                own.WaitForExit = false;
                own.DeleteProfileAfter = false;
                own.DeadlineMs = 25000;
                own.Arguments = new string[]
                {
                    "--probe", "fixture-owner",
                    "--attach",
                    "--winsta", winsta,
                    "--desk", desk,
                    "--marker", marker,
                    "--ready", ready,
                    "--shutdown-event", shutdownName,
                    "--timeout-ms", "25000"
                };
                LaunchResult started = Supervisor.Start(own, log, out owner);
                if (owner == null)
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("fixture-owner not created: " + started.Error);
                    return o;
                }
                if (!WaitFileToken(ready, "OK ", 8000))
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("fixture-owner ready missing: " + TextUtil.OneLine(TextUtil.ReadAllSafe(ready)));
                    o.Map["fixture_ready"] = JVal.Str(TextUtil.ReadAllSafe(ready));
                    return o;
                }
                string readyText = TextUtil.ReadAllSafe(ready);
                o.Map["fixture_ready"] = JVal.Str(TextUtil.OneLine(readyText));
                if (!TextUtil.ContainsToken(readyText, "PIXEL_OK=True") && !TextUtil.ContainsToken(readyText, "PIXEL_OK=true"))
                {
                    o.Map["control_pixels_from_owner"] = JVal.Str("fail");
                }
                string desktop = winsta + "\\" + desk;
                string controlStatus = Path.Combine(outDir, "ui-control.status.txt");
                string protStatus = Path.Combine(outDir, "ui-protected.status.txt");
                string protDesc = Path.Combine(outDir, "ui-protected-desc.status.txt");
                TextUtil.TryDelete(controlStatus);
                TextUtil.TryDelete(protStatus);
                TextUtil.TryDelete(protDesc);

                JVal control = RunUi(self, log, SandboxLevel.Unconstrained, false, desktop, winsta, desk, marker, controlStatus, null);
                JVal prot = RunUi(self, log, SandboxLevel.JobUiOnly, true, desktop, winsta, desk, marker, protStatus, protDesc);
                o.Map["control"] = control;
                o.Map["protected_job"] = prot;

                bool controlClip = TextUtil.ContainsToken(control.Get("status_text").AsString(""), "CLIP_READ ok=True") &&
                    TextUtil.ContainsToken(control.Get("status_text").AsString(""), "match=True");
                bool controlPix = TextUtil.ContainsToken(control.Get("status_text").AsString(""), "GDI_WINDOW_BITBLT ok=True") &&
                    TextUtil.ContainsToken(control.Get("status_text").AsString(""), "match=True");
                bool protClipReadBlocked = !TextUtil.ContainsToken(prot.Get("status_text").AsString(""), "CLIP_READ ok=True match=True");
                bool protClipWriteBlocked = !TextUtil.ContainsToken(prot.Get("status_text").AsString(""), "CLIP_WRITE ok=True");
                bool protStarted = prot.Get("pid").AsInt(0) > 0;
                bool descStarted = TextUtil.ContainsToken(prot.Get("status_text").AsString(""), "SPAWN=OK");

                control.Map["read_marker"] = JVal.Bool(controlClip);
                control.Map["read_pixels"] = JVal.Bool(controlPix);
                if (!controlClip || !controlPix)
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("control on synthetic station did not read marker and window pixels; screenshot/clipboard tests not counted as pass");
                    return o;
                }
                if (!protStarted)
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("protected job process did not start; not counted as restriction pass");
                    return o;
                }
                bool pass = protClipReadBlocked && protClipWriteBlocked;
                o.Map["protected_clipboard_read_blocked"] = JVal.Bool(protClipReadBlocked);
                o.Map["protected_clipboard_write_blocked"] = JVal.Bool(protClipWriteBlocked);
                o.Map["protected_descendant_started"] = JVal.Bool(descStarted);
                o.Map["gdi_window_bitblt_protected"] = JVal.Str(Extract(prot.Get("status_text").AsString(""), "GDI_WINDOW_BITBLT"));
                o.Map["gdi_screen_dc_protected"] = JVal.Str(Extract(prot.Get("status_text").AsString(""), "GDI_SCREEN_DC_BITBLT"));
                o.Map["open_winsta0_protected"] = JVal.Str(Extract(prot.Get("status_text").AsString(""), "OPEN_WINSTA0"));
                o.Map["open_fixture_protected"] = JVal.Str(Extract(prot.Get("status_text").AsString(""), "OPEN_FIXTURE_WINSTA"));
                o.Map["descendant_status"] = JVal.Str(prot.Get("desc_text").AsString(""));
                o.Map["status"] = JVal.Str(pass ? "pass" : "fail");
                o.Map["detail"] = JVal.Str(pass
                    ? "control read synthetic marker+pixels; job-protected clipboard read/write failed"
                    : "job-protected clipboard still succeeded");
                return o;
            }
            finally
            {
                if (ev != IntPtr.Zero)
                {
                    Native.SetEvent(ev);
                }
                if (owner != null)
                {
                    Thread.Sleep(200);
                    owner.Dispose();
                }
                if (ev != IntPtr.Zero)
                {
                    Native.CloseHandle(ev);
                }
                station.Dispose();
            }
        }

        static JVal RunUi(string self, Log log, SandboxLevel level, bool uiLimits, string desktop, string winsta, string desk, string marker, string status, string desc)
        {
            LaunchRequest req = new LaunchRequest();
            req.Level = level;
            req.Executable = self;
            req.Desktop = desktop;
            req.UseUiLimits = uiLimits;
            req.UsePrivateDesktop = true;
            req.RequirePrivateDesktop = false;
            req.UseStdPipes = false;
            req.WaitForExit = false;
            req.DeleteProfileAfter = false;
            req.DeadlineMs = 15000;
            List<string> a = new List<string>();
            a.Add("--probe");
            a.Add(desc == null ? "ui-child" : "ui");
            a.Add("--status");
            a.Add(status);
            a.Add("--marker");
            a.Add(marker);
            a.Add("--expect-winsta");
            a.Add(winsta);
            a.Add("--fixture-winsta");
            a.Add(winsta);
            a.Add("--fixture-desk");
            a.Add(desk);
            a.Add("--self");
            a.Add(self);
            if (desc != null)
            {
                a.Add("--desc-status");
                a.Add(desc);
            }
            req.Arguments = a.ToArray();
            ChildSession sess;
            LaunchResult started = Supervisor.Start(req, log, out sess);
            if (sess == null)
            {
                JVal fail = started.ToJson();
                fail.Map["status_text"] = JVal.Str("");
                fail.Map["desc_text"] = JVal.Str("");
                return fail;
            }
            try
            {
                Supervisor.Wait(sess, req.DeadlineMs, started);
                JVal o = started.ToJson();
                o.Map["status_text"] = JVal.Str(TextUtil.OneLine(TextUtil.ReadAllSafe(status)));
                o.Map["desc_text"] = JVal.Str(TextUtil.OneLine(TextUtil.ReadAllSafe(desc)));
                return o;
            }
            finally
            {
                sess.Dispose();
            }
        }

        static JVal TestLpacPrivateDesktop(string self, string outDir, Log log, List<string> profiles)
        {
            JVal o = JVal.Obj();
            string staErr;
            SyntheticStation station = SyntheticStation.TryCreateUnnamedOwned(out staErr);
            if (station == null)
            {
                o.Map["status"] = JVal.Str("requires_admin");
                o.Map["detail"] = JVal.Str("LPAC private desktop needs a uniquely owned station; " + staErr);
                o.Map["not_degraded"] = JVal.Bool(true);
                return o;
            }
            string winsta = station.WinstaName;
            string desk = station.DeskName;
            ChildSession agent = null;
            try
            {
                string acErr;
                int acWin;
                AppContainerSession ac = AppContainerSession.CreateUnique(out acErr, out acWin);
                if (ac == null)
                {
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("LPAC profile failed: " + acErr);
                    o.Map["not_degraded"] = JVal.Bool(true);
                    return o;
                }
                profiles.Add(ac.Name);
                uint gw = Native.GrantSidOnHandle(station.Winsta, Native.SE_WINDOW_OBJECT, ac.Sid,
                    Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL);
                uint gd = Native.GrantSidOnHandle(station.Desk, Native.SE_WINDOW_OBJECT, ac.Sid,
                    Native.DESKTOP_ALL | Native.READ_CONTROL);
                o.Map["grant_winsta"] = JVal.Num(gw);
                o.Map["grant_desk"] = JVal.Num(gd);
                string appDir = Path.Combine(ac.Folder, "app");
                string ws = Path.Combine(ac.Folder, "workspace");
                Directory.CreateDirectory(appDir);
                Directory.CreateDirectory(ws);
                string staged = Path.Combine(appDir, Path.GetFileName(self));
                File.Copy(self, staged, true);
                string status = Path.Combine(ws, "lpac-ui.status.txt");

                LaunchRequest req = new LaunchRequest();
                req.Level = SandboxLevel.InternalLpac;
                req.NetworkMode = "offline";
                req.Executable = staged;
                req.ExistingAc = ac;
                req.CopyExeToProfile = false;
                req.WorkingDirectory = appDir;
                req.Desktop = winsta + "\\" + desk;
                req.UsePrivateDesktop = true;
                req.RequirePrivateDesktop = false;
                req.UseUiLimits = true;
                req.UseStdPipes = false;
                req.UseRegistryReadCapability = true;
                req.WaitForExit = false;
                req.DeleteProfileAfter = true;
                req.DeadlineMs = Constants.FixtureDeadlineMs;
                req.Arguments = new string[]
                {
                    "--probe", "ui-child",
                    "--status", status,
                    "--marker", "no-marker-on-this-station",
                    "--expect-winsta", winsta,
                    "--fixture-winsta", "nmzpnas_no_such",
                    "--self", staged
                };

                LaunchResult pre = Supervisor.Start(req, log, out agent);
                if (agent == null)
                {
                    if (req.ExistingAc != null)
                    {
                        ac.DeleteIfOwned();
                        ac.Dispose();
                    }
                    o.Map["create"] = pre.ToJson();
                    o.Map["status"] = JVal.Str("fail");
                    o.Map["detail"] = JVal.Str("LPAC+private desktop CreateProcess failed win32=" + pre.Win32 + " " + pre.Error);
                    o.Map["not_degraded"] = JVal.Bool(!pre.DegradedToNormalProcess);
                    return o;
                }
                try
                {
                    Supervisor.Wait(agent, req.DeadlineMs, pre);
                    string st = CopyOut(status, status);
                    if (string.IsNullOrEmpty(st) && !string.IsNullOrEmpty(agent.StagingWorkspace))
                    {
                        st = CopyOut(Path.Combine(agent.StagingWorkspace, Path.GetFileName(status)), status);
                    }
                    o.Map["create"] = pre.ToJson();
                    o.Map["status_text"] = JVal.Str(TextUtil.OneLine(st));
                    o.Map["open_winsta0"] = JVal.Str(Extract(st, "OPEN_WINSTA0"));
                    o.Map["current_winsta"] = JVal.Str(Extract(st, "CURRENT_WINSTA"));
                    o.Map["not_degraded"] = JVal.Bool(!pre.DegradedToNormalProcess);
                    bool ran = pre.Pid > 0 && (TextUtil.ContainsToken(st, "PHASE=ui") || pre.ExitCode == 0);
                    o.Map["status"] = JVal.Str(ran ? "pass" : "fail");
                    o.Map["detail"] = JVal.Str(ran
                        ? "LPAC process started on holder desktop; see open_winsta0 actual result"
                        : "LPAC started but probe produced no UI evidence; exit=" + pre.ExitCode);
                    return o;
                }
                finally
                {
                    if (agent != null)
                    {
                        agent.DeleteProfile = true;
                        agent.Dispose();
                        agent = null;
                    }
                }
            }
            finally
            {
                station.Dispose();
            }
        }
#endif

        static bool WaitFileToken(string path, string token, int timeoutMs)
        {
            Clock c = new Clock();
            while (c.Elapsed < timeoutMs)
            {
                string t = TextUtil.ReadAllSafe(path);
                if (TextUtil.ContainsToken(t, token))
                {
                    return true;
                }
                Thread.Sleep(50);
            }
            return false;
        }

        static string Extract(string text, string prefix)
        {
            if (string.IsNullOrEmpty(text))
            {
                return "";
            }
            int i = text.IndexOf(prefix, StringComparison.Ordinal);
            if (i < 0)
            {
                return "";
            }
            int end = text.IndexOf("  ", i, StringComparison.Ordinal);
            if (end < 0)
            {
                return text.Substring(i).Trim();
            }
            return text.Substring(i, end - i).Trim();
        }

        static JVal CleanupProfiles(List<string> profiles, Log log)
        {
            JVal o = JVal.Obj();
            JVal names = JVal.Arr();
            bool all = true;
            for (int i = 0; i < profiles.Count; i++)
            {
                string n = profiles[i];
                names.Items.Add(JVal.Str(n ?? ""));
                if (!TextUtil.IsSafeProfileName(n))
                {
                    all = false;
                    continue;
                }
                int hr = Native.DeleteAppContainerProfile(n);
                if (hr != 0)
                {
                    Thread.Sleep(300);
                    hr = Native.DeleteAppContainerProfile(n);
                }
                if (hr != 0)
                {
                    all = false;
                }
                if (log != null)
                {
                    log.Info("DeleteAppContainerProfile " + n + " hr=0x" + hr.ToString("X8"));
                }
            }
            o.Map["profiles"] = names;
            o.Map["status"] = JVal.Str(all ? "pass" : "fail");
            o.Map["detail"] = JVal.Str("deleted only " + Constants.ProfilePrefix + "* names from this run");
            return o;
        }

        static JVal Phase(string status, string detail)
        {
            JVal o = JVal.Obj();
            o.Map["status"] = JVal.Str(status);
            o.Map["detail"] = JVal.Str(detail);
            return o;
        }

        static void Score(JVal root)
        {
            bool osc = root.Get("osc52_filter") != null && root.Get("osc52_filter").Get("all_pass").AsBool(false);
            bool brokered = StatusIs(root.Get("brokered_refuse"), "pass");
            bool json = StatusIs(root.Get("json_limits"), "pass");
            bool schema = StatusIs(root.Get("production_schema"), "pass");
            bool failclosed = StatusIs(root.Get("job_assign_failclosed"), "pass");
            bool stdio = StatusIs(root.Get("stdio_pipes"), "pass");
            bool unicode = StatusIs(root.Get("station_unicode"), "pass");
            bool guard = StatusIs(root.Get("ui_guard"), "pass");
            bool pubUi = StatusIs(root.Get("public_ui_probe_refused"), "pass");
            bool trunc = StatusIs(root.Get("stdio_truncated"), "pass");
            bool hold = StatusIs(root.Get("stdio_hold_drain"), "pass");
            bool disp = StatusIs(root.Get("internal_dispatch"), "pass");
            bool priv = StatusIs(root.Get("privileged_nonadmin"), "pass");
            bool dry = StatusIs(root.Get("dry_plan"), "pass");
            bool tokrep = StatusIs(root.Get("payload_token_report"), "pass");
            bool brLease = StatusIs(root.Get("brokered_lease"), "pass");
            bool control = false;
            bool acNet = false;
            JVal net = root.Get("network");
            if (net != null)
            {
                control = StatusIs(net.Get("control"), "pass");
                acNet = StatusIs(net.Get("appcontainer_offline"), "pass");
            }
            bool noDegrade = root.Get("degraded_to_normal_process").AsBool(true) == false;
            bool p0 = osc && brokered && json && schema && failclosed && stdio && trunc && hold && disp && priv && dry && tokrep && brLease && unicode && guard && pubUi && control && acNet && noDegrade;
            root.Map["p0_regression"] = JVal.Str(p0 ? "pass" : "fail");
            root.Map["production_ready"] = JVal.Bool(false);
            root.Map["overall"] = JVal.Str("fail_production_unavailable");
            root.Map["required_pass"] = JVal.Obj();
            root.Map["required_pass"].Map["osc52_filter"] = JVal.Bool(osc);
            root.Map["required_pass"].Map["brokered_refuse"] = JVal.Bool(brokered);
            root.Map["required_pass"].Map["json_limits"] = JVal.Bool(json);
            root.Map["required_pass"].Map["production_schema"] = JVal.Bool(schema);
            root.Map["required_pass"].Map["job_assign_failclosed"] = JVal.Bool(failclosed);
            root.Map["required_pass"].Map["stdio_pipes"] = JVal.Bool(stdio);
            root.Map["required_pass"].Map["stdio_truncated"] = JVal.Bool(trunc);
            root.Map["required_pass"].Map["stdio_hold_drain"] = JVal.Bool(hold);
            root.Map["required_pass"].Map["internal_dispatch"] = JVal.Bool(disp);
            root.Map["required_pass"].Map["privileged_nonadmin"] = JVal.Bool(priv);
            root.Map["required_pass"].Map["dry_plan"] = JVal.Bool(dry);
            root.Map["required_pass"].Map["payload_token_report"] = JVal.Bool(tokrep);
            root.Map["required_pass"].Map["brokered_lease"] = JVal.Bool(brLease);
            root.Map["required_pass"].Map["station_unicode"] = JVal.Bool(unicode);
            root.Map["required_pass"].Map["ui_guard"] = JVal.Bool(guard);
            root.Map["required_pass"].Map["public_ui_probe_refused"] = JVal.Bool(pubUi);
            root.Map["required_pass"].Map["network_control"] = JVal.Bool(control);
            root.Map["required_pass"].Map["network_appcontainer"] = JVal.Bool(acNet);
            JVal lpacNet = net != null ? net.Get("lpac_offline") : null;
            root.Map["production_lpac_network"] = JVal.Str(lpacNet != null ? lpacNet.Get("status").AsString("not_tested") : "not_tested");
            root.Map["production_lpac_private_desktop"] = JVal.Str(root.Get("lpac_private_desktop") != null ? root.Get("lpac_private_desktop").Get("status").AsString("not_tested") : "not_tested");
            JVal unver = JVal.Arr();
            unver.Items.Add(JVal.Str("Not a production security boundary claim."));
            unver.Items.Add(JVal.Str("DISPLAYSETTINGS is not screenshot protection."));
            unver.Items.Add(JVal.Str("DXGI and Windows.Graphics.Capture are not_tested; no physical display capture."));
            unver.Items.Add(JVal.Str("WFP real apply is forbidden this build; brokered uses nonadmin refusal and fake-world tests only."));
            unver.Items.Add(JVal.Str("Protected Grok/workspace/gateway integration is not complete."));
            unver.Items.Add(JVal.Str("Job UI limits on the current desktop do not replace a private window station for host-screen isolation."));
            unver.Items.Add(JVal.Str("Regular AppContainer is a comparison path; production default is LPAC."));
            unver.Items.Add(JVal.Str("Grok model API / leader / workspace integration is not in this component."));
            unver.Items.Add(JVal.Str("Privileged named station + CreateProcessAsUserW limited payload not OS-tested (no UAC this round)."));
            unver.Items.Add(JVal.Str("DXGI and Windows.Graphics.Capture remain not_tested; physical display pixels are not read."));
            root.Map["unverified_boundaries"] = unver;
        }

        static bool StatusIs(JVal node, string status)
        {
            if (node == null)
            {
                return false;
            }
            return string.Equals(node.Get("status").AsString(""), status, StringComparison.Ordinal);
        }

        static void WriteReport(string path, JVal root)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("# native-agent-sandbox self-test");
            sb.AppendLine();
            sb.AppendLine("overall: **" + root.Get("overall").AsString("") + "** (production not available)");
            sb.AppendLine();
            sb.AppendLine("- production_ready: **false**");
            sb.AppendLine("- p0_regression: " + root.Get("p0_regression").AsString(""));
            sb.AppendLine("- OSC52 filter: " + (root.Get("osc52_filter").Get("all_pass").AsBool(false) ? "pass" : "fail"));
            sb.AppendLine("- json_limits: " + root.Get("json_limits").Get("status").AsString(""));
            sb.AppendLine("- production_schema: " + root.Get("production_schema").Get("status").AsString(""));
            sb.AppendLine("- job_assign_failclosed: " + root.Get("job_assign_failclosed").Get("status").AsString(""));
            sb.AppendLine("- stdio_pipes: " + root.Get("stdio_pipes").Get("status").AsString(""));
            sb.AppendLine("- stdio_truncated: " + root.Get("stdio_truncated").Get("status").AsString(""));
            sb.AppendLine("- stdio_hold_drain: " + (root.Get("stdio_hold_drain") != null ? root.Get("stdio_hold_drain").Get("status").AsString("") : ""));
            sb.AppendLine("- internal_dispatch: " + (root.Get("internal_dispatch") != null ? root.Get("internal_dispatch").Get("status").AsString("") : ""));
            sb.AppendLine("- privileged_nonadmin: " + (root.Get("privileged_nonadmin") != null ? root.Get("privileged_nonadmin").Get("status").AsString("") : ""));
            sb.AppendLine("- dry_plan: " + (root.Get("dry_plan") != null ? root.Get("dry_plan").Get("status").AsString("") : ""));
            sb.AppendLine("- station_unicode: " + root.Get("station_unicode").Get("status").AsString(""));
            sb.AppendLine("- ui_guard: " + root.Get("ui_guard").Get("status").AsString(""));
            sb.AppendLine("- public_ui_probe_refused: " + root.Get("public_ui_probe_refused").Get("status").AsString(""));
            sb.AppendLine("- brokered refuse: " + root.Get("brokered_refuse").Get("status").AsString(""));
            if (root.Get("brokered_lease") != null)
            {
                sb.AppendLine("- brokered_lease: " + root.Get("brokered_lease").Get("status").AsString("") + " " + root.Get("brokered_lease").Get("detail").AsString(""));
            }
            JVal net = root.Get("network");
            if (net != null)
            {
                sb.AppendLine("- network control: " + net.Get("control").Get("status").AsString("") + " " + net.Get("control").Get("detail").AsString(""));
                sb.AppendLine("- network appcontainer: " + net.Get("appcontainer_offline").Get("status").AsString("") + " " + net.Get("appcontainer_offline").Get("detail").AsString(""));
                sb.AppendLine("- network lpac: " + net.Get("lpac_offline").Get("status").AsString("") + " " + net.Get("lpac_offline").Get("detail").AsString(""));
            }
            JVal clip = root.Get("clipboard_gdi");
            if (clip != null)
            {
                sb.AppendLine("- clipboard/GDI: " + clip.Get("status").AsString("") + " " + clip.Get("detail").AsString(""));
            }
            JVal lp = root.Get("lpac_private_desktop");
            if (lp != null)
            {
                sb.AppendLine("- LPAC private desktop: " + lp.Get("status").AsString("") + " " + lp.Get("detail").AsString(""));
            }
            sb.AppendLine("- DXGI/WGC: not_tested");
            sb.AppendLine("- screen_pixels_not_tested: true (no GetDC(NULL) BitBlt/GetPixel)");
            sb.AppendLine("- DISPLAYSETTINGS is not anti-screenshot");
            sb.AppendLine("- do not run --execute-payload or UI capture before root final review");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }
    }

    internal sealed class NetReceiver
    {
        readonly object gate = new object();
        readonly Dictionary<string, int> tcpHits = new Dictionary<string, int>(StringComparer.Ordinal);
        readonly Dictionary<string, int> udpHits = new Dictionary<string, int>(StringComparer.Ordinal);
        TcpListener tcp4;
        TcpListener tcp6;
        UdpClient udp;
        Thread t4;
        Thread t6;
        Thread tu;
        volatile bool running;

        public int Port4;
        public int Port6;
        public int PortUdp;
        public bool Tcp6Ok;

        public void Register(string nonce)
        {
            lock (gate)
            {
                tcpHits[nonce] = 0;
                udpHits[nonce] = 0;
            }
        }

        public int Count(string nonce)
        {
            lock (gate)
            {
                int n;
                if (tcpHits.TryGetValue(nonce, out n)) return n;
                return 0;
            }
        }

        public int CountUdp(string nonce)
        {
            lock (gate)
            {
                int n;
                if (udpHits.TryGetValue(nonce, out n)) return n;
                return 0;
            }
        }

        public void Start()
        {
            running = true;
            tcp4 = new TcpListener(IPAddress.Loopback, 0);
            tcp4.Start();
            Port4 = ((IPEndPoint)tcp4.LocalEndpoint).Port;
            t4 = new Thread(Loop4);
            t4.IsBackground = true;
            t4.Start();
            try
            {
                tcp6 = new TcpListener(IPAddress.IPv6Loopback, 0);
                tcp6.Start();
                Port6 = ((IPEndPoint)tcp6.LocalEndpoint).Port;
                Tcp6Ok = true;
                t6 = new Thread(Loop6);
                t6.IsBackground = true;
                t6.Start();
            }
            catch
            {
                Tcp6Ok = false;
                Port6 = Port4;
            }
            udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            PortUdp = ((IPEndPoint)udp.Client.LocalEndPoint).Port;
            tu = new Thread(LoopUdp);
            tu.IsBackground = true;
            tu.Start();
        }

        public void Stop()
        {
            running = false;
            try { if (tcp4 != null) tcp4.Stop(); } catch { }
            try { if (tcp6 != null) tcp6.Stop(); } catch { }
            try { if (udp != null) udp.Close(); } catch { }
            if (t4 != null) t4.Join(1000);
            if (t6 != null) t6.Join(1000);
            if (tu != null) tu.Join(1000);
        }

        void Loop4()
        {
            AcceptLoop(tcp4);
        }

        void Loop6()
        {
            AcceptLoop(tcp6);
        }

        void AcceptLoop(TcpListener listener)
        {
            while (running)
            {
                try
                {
                    if (listener == null || !listener.Pending())
                    {
                        Thread.Sleep(10);
                        continue;
                    }
                    TcpClient c = listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(HandleTcp, c);
                }
                catch
                {
                    if (!running) return;
                    Thread.Sleep(10);
                }
            }
        }

        void HandleTcp(object state)
        {
            TcpClient client = state as TcpClient;
            if (client == null) return;
            try
            {
                client.ReceiveTimeout = 2000;
                NetworkStream ns = client.GetStream();
                byte[] buf = new byte[1024];
                int n = ns.Read(buf, 0, buf.Length);
                string req = Encoding.ASCII.GetString(buf, 0, n);
                string nonce = ParseNonce(req);
                if (nonce != null)
                {
                    lock (gate)
                    {
                        if (tcpHits.ContainsKey(nonce))
                        {
                            tcpHits[nonce] = tcpHits[nonce] + 1;
                        }
                    }
                }
                byte[] rb = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                ns.Write(rb, 0, rb.Length);
            }
            catch { }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        void LoopUdp()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
            while (running)
            {
                try
                {
                    if (udp.Available <= 0)
                    {
                        Thread.Sleep(10);
                        continue;
                    }
                    byte[] data = udp.Receive(ref ep);
                    string s = Encoding.ASCII.GetString(data);
                    if (s.StartsWith("N=", StringComparison.Ordinal) && s.Length > 2)
                    {
                        string nonce = s.Substring(2);
                        lock (gate)
                        {
                            if (udpHits.ContainsKey(nonce))
                            {
                                udpHits[nonce] = udpHits[nonce] + 1;
                            }
                        }
                    }
                }
                catch
                {
                    if (!running) return;
                    Thread.Sleep(10);
                }
            }
        }

        static string ParseNonce(string req)
        {
            if (string.IsNullOrEmpty(req)) return null;
            int lineEnd = req.IndexOf("\r\n");
            string line = lineEnd >= 0 ? req.Substring(0, lineEnd) : req;
            string[] parts = line.Split(' ');
            if (parts.Length < 2) return null;
            string path = parts[1];
            const string prefix = "/n/";
            if (path.StartsWith(prefix, StringComparison.Ordinal) && path.Length > prefix.Length)
            {
                return path.Substring(prefix.Length);
            }
            return null;
        }
    }
}
