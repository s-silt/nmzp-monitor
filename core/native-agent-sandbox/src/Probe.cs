using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NativeAgentSandbox
{
    internal static class FixtureGuard
    {
        public static int ClipboardApiEntered;
        public static int CaptureApiEntered;
        public static int Blocked;

        public static bool TryAllow(string expectSta, string expectDesk, out string reason)
        {
            reason = "";
            string curSta;
            if (!Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out curSta))
            {
                Blocked++;
                reason = "station_name_unknown";
                return false;
            }
            if (string.IsNullOrEmpty(curSta) || string.Equals(curSta, "unknown", StringComparison.Ordinal))
            {
                Blocked++;
                reason = "station_name_empty";
                return false;
            }
            if (Native.IsWinSta0Name(curSta))
            {
                Blocked++;
                reason = "winsta0";
                return false;
            }
            if (string.IsNullOrEmpty(expectSta) || string.IsNullOrEmpty(expectDesk))
            {
                Blocked++;
                reason = "no_fixture_context";
                return false;
            }
            if (Native.IsWinSta0Name(expectSta))
            {
                Blocked++;
                reason = "expect_winsta0";
                return false;
            }
            if (!string.Equals(curSta, expectSta, StringComparison.Ordinal))
            {
                Blocked++;
                reason = "station_mismatch";
                return false;
            }
            string curDesk;
            if (!Native.TryGetUserObjectName(Native.GetThreadDesktop(Native.GetCurrentThreadId()), out curDesk))
            {
                Blocked++;
                reason = "desktop_name_unknown";
                return false;
            }
            if (!string.Equals(curDesk, expectDesk, StringComparison.Ordinal))
            {
                Blocked++;
                reason = "desktop_mismatch";
                return false;
            }
            string token = Environment.GetEnvironmentVariable("NMZP_NAS_FIXTURE_TOKEN");
            string ownedSta = Environment.GetEnvironmentVariable("NMZP_NAS_FIXTURE_STATION");
            string ownedDesk = Environment.GetEnvironmentVariable("NMZP_NAS_FIXTURE_DESK");
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(ownedSta) || string.IsNullOrEmpty(ownedDesk))
            {
                Blocked++;
                reason = "ownership_missing";
                return false;
            }
            if (!string.Equals(ownedSta, expectSta, StringComparison.Ordinal) ||
                !string.Equals(ownedDesk, expectDesk, StringComparison.Ordinal))
            {
                Blocked++;
                reason = "ownership_mismatch";
                return false;
            }
            return true;
        }
    }

    internal static class Probe
    {
        static Native.WndProc FixtureProcKeepAlive;

        public static int Run(string[] args)
        {
            string mode = Args.Get(args, "--probe");
            if (string.IsNullOrEmpty(mode))
            {
                mode = "help";
            }
            try
            {
                if (mode == "stdout-big")
                {
                    byte[] block = Encoding.ASCII.GetBytes(new string('A', 4096));
                    int left = 1024 * 1024 + 8192;
                    Stream stdout = Console.OpenStandardOutput();
                    while (left > 0)
                    {
                        int n = left < block.Length ? left : block.Length;
                        stdout.Write(block, 0, n);
                        left -= n;
                    }
                    byte[] end = Encoding.ASCII.GetBytes("END");
                    stdout.Write(end, 0, end.Length);
                    stdout.Flush();
                    return 0;
                }
                if (mode == "stdout-osc")
                {
                    Console.Write("pre\u001b]52;c;QUJDRA==\u0007NMZP_STDOUT_OK");
                    Console.Error.Write("err-ok");
                    return 0;
                }
                if (mode == "stdout-hold-child")
                {
                    string evName = Args.Get(args, "--shutdown-event");
                    int timeoutMs = Args.GetInt(args, "--timeout-ms", 8000);
                    if (timeoutMs < 200) timeoutMs = 200;
                    if (timeoutMs > 15000) timeoutMs = 15000;
                    IntPtr ev = IntPtr.Zero;
                    if (!string.IsNullOrEmpty(evName))
                    {
                        ev = Native.OpenEvent(Native.SYNCHRONIZE, false, evName);
                    }
                    Clock clock = new Clock();
                    while (clock.Elapsed < timeoutMs)
                    {
                        if (ev != IntPtr.Zero)
                        {
                            uint w = Native.WaitForSingleObject(ev, 50);
                            if (w == Native.WAIT_OBJECT_0)
                            {
                                break;
                            }
                        }
                        else
                        {
                            Thread.Sleep(50);
                        }
                    }
                    return 0;
                }
                if (mode == "stdout-hold-stderr-flood")
                {
                    string self = Assembly.GetExecutingAssembly().Location;
                    string evName = Args.Get(args, "--shutdown-event");
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = self;
                    psi.Arguments = TextUtil.BuildArguments(new string[]
                    {
                        "--probe", "stdout-hold-child",
                        "--shutdown-event", evName ?? "",
                        "--timeout-ms", "8000"
                    });
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    Process.Start(psi);
                    Stream err = Console.OpenStandardError();
                    byte[] block = Encoding.ASCII.GetBytes(new string('E', 4096));
                    for (int i = 0; i < 400; i++)
                    {
                        err.Write(block, 0, block.Length);
                    }
                    err.Flush();
                    return 0;
                }
                if (mode == "payload-token-report")
                {
                    JVal report = TokenBridge.InspectCurrent();
                    string statusPath = Args.Get(args, "--status");
                    string line = "TOKEN_ELEVATION_TYPE=" + report.GetInt("elevation_type", 0) +
                        " TOKEN_IS_ELEVATED=" + report.GetBool("token_is_elevated", true) +
                        " ADMIN_ENABLED=" + report.GetBool("admin_sid_enabled", true) +
                        " SESSION_ID=" + report.GetInt("session_id", -1) +
                        " USER_SID_LEN=" + report.GetInt("user_sid_len", 0) +
                        " IS_APPCONTAINER=" + report.GetBool("is_appcontainer", false) +
                        " PACKAGE_SID_LEN=" + report.GetInt("package_sid_len", 0) +
                        " IN_JOB=" + report.GetBool("in_job", false) +
                        " QUERIES_OK=" + report.GetBool("queries_ok", false) +
                        " ERR=" + report.GetStr("error", "");
                    TextUtil.WriteStatus(statusPath, line);
                    Console.Write(Json.Stringify(report));
                    return report.GetBool("queries_ok", false) ? 0 : 1;
                }
                if (mode == "payload-marker")
                {
                    string marker = Args.Get(args, "--marker-file");
                    if (string.IsNullOrEmpty(marker))
                    {
                        return 99;
                    }
                    File.WriteAllText(marker, "PAYLOAD_RAN\n", Encoding.ASCII);
                    return 0;
                }
                if (mode == "net" || mode == "net-once")
                {
                    return ProbeNet(args, mode == "net");
                }
                if (mode == "station-name")
                {
                    return ProbeStationName(args);
                }
                if (mode == "ui-guard")
                {
                    return ProbeUiGuard(args);
                }
                if (mode == "winsta-holder" || mode == "fixture-owner" || mode == "ui" || mode == "ui-child")
                {
                    string ticket = Args.Get(args, "--dispatch-ticket");
                    string derr;
                    if (string.IsNullOrEmpty(ticket) || !InternalDispatch.TryValidate(ticket, mode, out derr))
                    {
                        TextUtil.WriteStatus(Args.Get(args, "--status"), "REFUSED=public_ui_probe");
                        TextUtil.WriteStatus(Args.Get(args, "--ready"), "REFUSED=public_ui_probe");
                        return 2;
                    }
                }
                if (mode == "winsta-holder")
                {
                    return ProbeWinstaHolder(args);
                }
                if (mode == "fixture-owner")
                {
                    return ProbeFixtureOwner(args);
                }
                if (mode == "ui")
                {
                    return ProbeUi(args, true);
                }
                if (mode == "ui-child")
                {
                    return ProbeUi(args, false);
                }
                TextUtil.WriteStatus(Args.Get(args, "--status"), "REFUSED=unknown_mode");
                return 99;
            }
            catch (Exception ex)
            {
                TextUtil.AppendStatus(Args.Get(args, "--status"), "FATAL=" + TextUtil.Sanitize(ex.GetType().Name + " " + ex.Message));
                return 12;
            }
        }

        static int ProbeStationName(string[] args)
        {
            string statusPath = Args.Get(args, "--status");
            string name;
            bool ok = Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out name);
            TextUtil.WriteStatus(statusPath,
                "CURRENT_WINSTA=" + name +
                " UNICODE_WINSTA0=" + Native.IsWinSta0Name(name) +
                " ok=" + ok +
                " CLIPBOARD_API=" + FixtureGuard.ClipboardApiEntered +
                " CAPTURE_API=" + FixtureGuard.CaptureApiEntered);
            return ok ? 0 : 1;
        }

        static int ProbeUiGuard(string[] args)
        {
            string statusPath = Args.Get(args, "--status");
            int clip0 = FixtureGuard.ClipboardApiEntered;
            int cap0 = FixtureGuard.CaptureApiEntered;
            string r1;
            string r2;
            string r3;
            bool a1 = FixtureGuard.TryAllow("", "", out r1);
            bool a2 = FixtureGuard.TryAllow("WinSta0", "Default", out r2);
            string cur;
            Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out cur);
            bool a3 = FixtureGuard.TryAllow(cur, "Default", out r3);
            string dummy;
            int win32;
            TryReadClipboard("WinSta0", "Default", out dummy, out win32);
            int screenWin;
            bool screenHandle;
            ProbeScreenAccess("WinSta0", "Default", out screenHandle, out screenWin);
            int clipDelta = FixtureGuard.ClipboardApiEntered - clip0;
            int capDelta = FixtureGuard.CaptureApiEntered - cap0;
            TextUtil.WriteStatus(statusPath,
                "CURRENT_WINSTA=" + cur +
                " UNICODE_WINSTA0=" + Native.IsWinSta0Name(cur) +
                " allow_empty=" + a1 + " reason1=" + r1 +
                " allow_winsta0=" + a2 + " reason2=" + r2 +
                " allow_current=" + a3 + " reason3=" + r3 +
                " CLIPBOARD_API_DELTA=" + clipDelta +
                " CAPTURE_API_DELTA=" + capDelta +
                " BLOCKED=" + FixtureGuard.Blocked);
            bool pass = Native.IsWinSta0Name(cur) && !a1 && !a2 && !a3 && clipDelta == 0 && capDelta == 0;
            return pass ? 0 : 1;
        }

        static int ProbeNet(string[] args, bool spawnChild)
        {
            string statusPath = Args.Get(args, "--status");
            string dirA = Args.Get(args, "--dir-a");
            string dirB = Args.Get(args, "--dir-b");
            string payloadName = Args.Get(args, "--payload-name");
            if (string.IsNullOrEmpty(payloadName))
            {
                payloadName = "payload.txt";
            }
            string host4 = Args.Get(args, "--host4");
            string host6 = Args.Get(args, "--host6");
            int port4 = Args.GetInt(args, "--port4", 0);
            int port6 = Args.GetInt(args, "--port6", 0);
            int portUdp = Args.GetInt(args, "--port-udp", 0);
            string nonce = Args.Get(args, "--nonce");
            int timeoutMs = Args.GetInt(args, "--timeout-ms", Constants.ProbeConnectTimeoutMs);
            if (timeoutMs < 200) timeoutMs = 200;
            if (timeoutMs > 8000) timeoutMs = 8000;

            TextUtil.WriteStatus(statusPath, "PHASE=net");
            string payload = "";
            if (!string.IsNullOrEmpty(dirA))
            {
                try
                {
                    string p = Path.Combine(dirA, payloadName);
                    payload = File.ReadAllText(p, Encoding.ASCII);
                    TextUtil.AppendStatus(statusPath, "FILE_READ=OK LEN=" + payload.Length);
                }
                catch (Exception ex)
                {
                    TextUtil.AppendStatus(statusPath, "FILE_READ=FAIL " + TextUtil.Sanitize(ex.GetType().Name));
                    return 20;
                }
            }
            else
            {
                TextUtil.AppendStatus(statusPath, "FILE_READ=SKIP");
            }
            if (!string.IsNullOrEmpty(dirB))
            {
                try
                {
                    Directory.CreateDirectory(dirB);
                    File.WriteAllText(Path.Combine(dirB, "echo.txt"), payload + ":" + nonce, Encoding.ASCII);
                    TextUtil.AppendStatus(statusPath, "FILE_WRITE=OK");
                }
                catch (Exception ex)
                {
                    TextUtil.AppendStatus(statusPath, "FILE_WRITE=FAIL " + TextUtil.Sanitize(ex.GetType().Name));
                    return 21;
                }
            }

            if (string.IsNullOrEmpty(nonce) || port4 <= 0)
            {
                TextUtil.AppendStatus(statusPath, "REFUSED=bad_net_args");
                return 99;
            }

            int tcp4 = AttemptTcp(host4, port4, nonce, timeoutMs, statusPath, "TCP4");
            int tcp6 = 0;
            if (port6 > 0 && !string.IsNullOrEmpty(host6))
            {
                tcp6 = AttemptTcp(host6, port6, nonce, timeoutMs, statusPath, "TCP6");
            }
            else
            {
                TextUtil.AppendStatus(statusPath, "TCP6=SKIP");
            }
            int udp = 0;
            if (portUdp > 0)
            {
                udp = AttemptUdp(host4, portUdp, nonce, timeoutMs, statusPath);
            }
            else
            {
                TextUtil.AppendStatus(statusPath, "UDP=SKIP");
            }

            if (spawnChild)
            {
                string self = Args.Get(args, "--self");
                if (string.IsNullOrEmpty(self))
                {
                    self = Assembly.GetExecutingAssembly().Location;
                }
                string childStatus = Args.Get(args, "--desc-status");
                try
                {
                    if (!File.Exists(self))
                    {
                        TextUtil.AppendStatus(statusPath, "SPAWN=FAIL exe_missing");
                        return 13;
                    }
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = self;
                    psi.Arguments = TextUtil.BuildArguments(new string[]
                    {
                        "--probe", "net-once",
                        "--host4", host4,
                        "--port4", port4.ToString(),
                        "--host6", host6 ?? "",
                        "--port6", port6.ToString(),
                        "--port-udp", portUdp.ToString(),
                        "--nonce", nonce + "d",
                        "--status", childStatus,
                        "--timeout-ms", timeoutMs.ToString(),
                        "--dir-a", dirA ?? "",
                        "--dir-b", dirB ?? "",
                        "--payload-name", payloadName
                    });
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.WindowStyle = ProcessWindowStyle.Hidden;
                    string wd = Path.GetDirectoryName(self);
                    if (!string.IsNullOrEmpty(wd))
                    {
                        psi.WorkingDirectory = wd;
                    }
                    Process child = Process.Start(psi);
                    if (child == null)
                    {
                        TextUtil.AppendStatus(statusPath, "SPAWN=FAIL start_returned_null");
                        return 13;
                    }
                    TextUtil.AppendStatus(statusPath, "SPAWN=OK PID=" + child.Id);
                    if (!child.WaitForExit(Constants.DescendantWaitMs))
                    {
                        try { child.Kill(); }
                        catch { }
                        TextUtil.AppendStatus(statusPath, "DESCENDANT=TIMEOUT");
                    }
                    else
                    {
                        TextUtil.AppendStatus(statusPath, "DESCENDANT_EXIT=" + child.ExitCode);
                    }
                }
                catch (Exception ex)
                {
                    TextUtil.AppendStatus(statusPath, "SPAWN=FAIL TYPE=" + ex.GetType().Name + " MSG=" + TextUtil.Sanitize(ex.Message));
                    return 13;
                }
            }

            TextUtil.AppendStatus(statusPath, "NET_DONE tcp4=" + tcp4 + " tcp6=" + tcp6 + " udp=" + udp);
            return 0;
        }

        static int AttemptTcp(string host, int port, string nonce, int timeoutMs, string statusPath, string tag)
        {
            TcpClient client = null;
            try
            {
                TextUtil.AppendStatus(statusPath, tag + "=ATTEMPT");
                if (string.Equals(host, "::1", StringComparison.Ordinal) || string.Equals(host, "[::1]", StringComparison.Ordinal))
                {
                    client = new TcpClient(AddressFamily.InterNetworkV6);
                    IAsyncResult ar = client.BeginConnect(IPAddress.IPv6Loopback, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    {
                        TextUtil.AppendStatus(statusPath, tag + "=TIMEOUT");
                        TryClose(client);
                        return 10;
                    }
                    client.EndConnect(ar);
                }
                else
                {
                    client = new TcpClient();
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    {
                        TextUtil.AppendStatus(statusPath, tag + "=TIMEOUT");
                        TryClose(client);
                        return 10;
                    }
                    client.EndConnect(ar);
                }
                client.ReceiveTimeout = timeoutMs;
                client.SendTimeout = timeoutMs;
                NetworkStream ns = client.GetStream();
                byte[] req = Encoding.ASCII.GetBytes(
                    "GET /n/" + nonce + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
                ns.Write(req, 0, req.Length);
                ns.Flush();
                byte[] buf = new byte[256];
                int n = 0;
                try
                {
                    n = ns.Read(buf, 0, buf.Length);
                }
                catch (Exception readEx)
                {
                    TextUtil.AppendStatus(statusPath, tag + "=OK_NO_READ " + readEx.GetType().Name);
                    return 0;
                }
                TextUtil.AppendStatus(statusPath, tag + "=OK BYTES=" + n);
                return 0;
            }
            catch (SocketException se)
            {
                TextUtil.AppendStatus(statusPath, tag + "=FAIL SOCKET=" + se.ErrorCode);
                return 10;
            }
            catch (Exception ex)
            {
                SocketException inner = ex.InnerException as SocketException;
                if (inner != null)
                {
                    TextUtil.AppendStatus(statusPath, tag + "=FAIL SOCKET=" + inner.ErrorCode + " WRAP=" + ex.GetType().Name);
                    return 10;
                }
                TextUtil.AppendStatus(statusPath, tag + "=FAIL TYPE=" + ex.GetType().Name + " MSG=" + TextUtil.Sanitize(ex.Message));
                return 12;
            }
            finally
            {
                TryClose(client);
            }
        }

        static int AttemptUdp(string host, int port, string nonce, int timeoutMs, string statusPath)
        {
            UdpClient udp = null;
            try
            {
                TextUtil.AppendStatus(statusPath, "UDP=ATTEMPT");
                udp = new UdpClient(AddressFamily.InterNetwork);
                byte[] data = Encoding.ASCII.GetBytes("N=" + nonce);
                udp.Send(data, data.Length, host, port);
                TextUtil.AppendStatus(statusPath, "UDP=SENT BYTES=" + data.Length);
                return 0;
            }
            catch (SocketException se)
            {
                TextUtil.AppendStatus(statusPath, "UDP=FAIL SOCKET=" + se.ErrorCode);
                return 10;
            }
            catch (Exception ex)
            {
                TextUtil.AppendStatus(statusPath, "UDP=FAIL TYPE=" + ex.GetType().Name + " MSG=" + TextUtil.Sanitize(ex.Message));
                return 12;
            }
            finally
            {
                try
                {
                    if (udp != null) udp.Close();
                }
                catch { }
            }
        }

        static void TryClose(TcpClient client)
        {
            if (client == null) return;
            try { client.Close(); }
            catch { }
        }

        static int ProbeWinstaHolder(string[] args)
        {
            string winstaName = Args.Get(args, "--winsta");
            string deskName = Args.Get(args, "--desk");
            string readyPath = Args.Get(args, "--ready");
            string grantPath = Args.Get(args, "--grant-sid-file");
            string shutdownName = Args.Get(args, "--shutdown-event");
            int timeoutMs = Args.GetInt(args, "--timeout-ms", 25000);
            if (string.IsNullOrEmpty(winstaName) || string.IsNullOrEmpty(deskName))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=missing_names");
                return 2;
            }

            IntPtr winsta = Native.CreateWindowStation(winstaName, Native.CWF_CREATE_ONLY,
                Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL | Native.WRITE_DAC | Native.WRITE_OWNER | Native.DELETE_RIGHT,
                IntPtr.Zero);
            if (winsta == IntPtr.Zero)
            {
                TextUtil.WriteStatus(readyPath, "FAIL=CreateWindowStation win32=" + Marshal.GetLastWin32Error());
                return 5;
            }
            if (!Native.SetProcessWindowStation(winsta))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=SetProcessWindowStation win32=" + Marshal.GetLastWin32Error());
                return 5;
            }
            IntPtr desk = Native.CreateDesktop(deskName, IntPtr.Zero, IntPtr.Zero, 0,
                Native.DESKTOP_ALL | Native.READ_CONTROL | Native.WRITE_DAC | Native.WRITE_OWNER | Native.DELETE_RIGHT,
                IntPtr.Zero);
            if (desk == IntPtr.Zero)
            {
                TextUtil.WriteStatus(readyPath, "FAIL=CreateDesktop win32=" + Marshal.GetLastWin32Error());
                return 5;
            }
            if (!Native.SetThreadDesktop(desk))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=SetThreadDesktop win32=" + Marshal.GetLastWin32Error());
                return 5;
            }

            string confirmSta = Native.GetUserObjectName(Native.GetProcessWindowStation());
            if (string.Equals(confirmSta, "WinSta0", StringComparison.OrdinalIgnoreCase))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=still_on_WinSta0");
                return 5;
            }
            TextUtil.WriteStatus(readyPath, "OK WINSTA=" + confirmSta + " DESK=" + deskName + " DESKTOP=" + confirmSta + "\\" + deskName);

            IntPtr shutdown = IntPtr.Zero;
            if (!string.IsNullOrEmpty(shutdownName))
            {
                shutdown = Native.OpenEvent(Native.SYNCHRONIZE, false, shutdownName);
            }
            Clock clock = new Clock();
            bool granted = false;
            while (clock.Elapsed < timeoutMs)
            {
                if (shutdown != IntPtr.Zero)
                {
                    uint w = Native.WaitForSingleObject(shutdown, 50);
                    if (w == Native.WAIT_OBJECT_0)
                    {
                        break;
                    }
                }
                else
                {
                    Thread.Sleep(50);
                }
                if (!granted && !string.IsNullOrEmpty(grantPath) && File.Exists(grantPath))
                {
                    try
                    {
                        string sidText = File.ReadAllText(grantPath, Encoding.ASCII).Trim();
                        IntPtr sid;
                        if (!string.IsNullOrEmpty(sidText) && Native.ConvertStringSidToSid(sidText, out sid) && sid != IntPtr.Zero)
                        {
                            uint gw = Native.GrantSidOnHandle(winsta, Native.SE_WINDOW_OBJECT, sid,
                                Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL);
                            uint gd = Native.GrantSidOnHandle(desk, Native.SE_WINDOW_OBJECT, sid,
                                Native.DESKTOP_ALL | Native.READ_CONTROL);
                            TextUtil.AppendStatus(readyPath, "GRANT winsta=" + gw + " desk=" + gd);
                            Native.LocalFree(sid);
                            granted = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        TextUtil.AppendStatus(readyPath, "GRANT_FAIL " + TextUtil.Sanitize(ex.Message));
                    }
                }
            }
            return 0;
        }

        static int ProbeFixtureOwner(string[] args)
        {
            string winstaName = Args.Get(args, "--winsta");
            string deskName = Args.Get(args, "--desk");
            string readyPath = Args.Get(args, "--ready");
            string marker = Args.Get(args, "--marker");
            string shutdownName = Args.Get(args, "--shutdown-event");
            int timeoutMs = Args.GetInt(args, "--timeout-ms", 25000);
            if (string.IsNullOrEmpty(winstaName) || string.IsNullOrEmpty(deskName) || string.IsNullOrEmpty(marker))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=missing_args");
                return 2;
            }
            if (Native.IsWinSta0Name(winstaName))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=refused_winsta0");
                return 2;
            }

            bool attach = Args.HasFlag(args, "--attach");
            IntPtr winsta;
            IntPtr desk;
            if (attach)
            {
                winsta = Native.OpenWindowStation(winstaName, false,
                    Native.WINSTA_ALL_ACCESS | Native.READ_CONTROL);
                if (winsta == IntPtr.Zero)
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=OpenWindowStation win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
                if (!Native.SetProcessWindowStation(winsta))
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=SetProcessWindowStation win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
                desk = Native.OpenDesktop(deskName, 0, false, Native.DESKTOP_ALL);
                if (desk == IntPtr.Zero)
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=OpenDesktop win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
            }
            else
            {
                winsta = Native.CreateWindowStation(winstaName, 0, Native.WINSTA_ALL_ACCESS, IntPtr.Zero);
                if (winsta == IntPtr.Zero)
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=CreateWindowStation win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
                if (!Native.SetProcessWindowStation(winsta))
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=SetProcessWindowStation win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
                desk = Native.CreateDesktop(deskName, IntPtr.Zero, IntPtr.Zero, 0,
                    Native.DESKTOP_ALL | Native.READ_CONTROL | Native.WRITE_DAC, IntPtr.Zero);
                if (desk == IntPtr.Zero)
                {
                    TextUtil.WriteStatus(readyPath, "FAIL=CreateDesktop win32=" + Marshal.GetLastWin32Error());
                    return 5;
                }
            }
            if (!Native.SetThreadDesktop(desk))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=SetThreadDesktop win32=" + Marshal.GetLastWin32Error());
                return 5;
            }
            string staName;
            if (!Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out staName) ||
                Native.IsWinSta0Name(staName) ||
                !string.Equals(staName, winstaName, StringComparison.Ordinal))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=station_mismatch_or_winsta0 name=" + staName);
                return 5;
            }
            string gotDesk;
            if (!Native.TryGetUserObjectName(Native.GetThreadDesktop(Native.GetCurrentThreadId()), out gotDesk) ||
                !string.Equals(gotDesk, deskName, StringComparison.Ordinal))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=desktop_mismatch name=" + gotDesk);
                return 5;
            }
            string allowReason;
            if (!FixtureGuard.TryAllow(winstaName, deskName, out allowReason))
            {
                TextUtil.WriteStatus(readyPath, "FAIL=fixture_guard " + allowReason);
                return 2;
            }

            IntPtr hwnd = CreateFixtureWindow();
            if (hwnd == IntPtr.Zero)
            {
                TextUtil.WriteStatus(readyPath, "FAIL=CreateWindowEx win32=" + Marshal.GetLastWin32Error());
                return 6;
            }
            Native.ShowWindow(hwnd, Native.SW_SHOW);
            Native.UpdateWindow(hwnd);
            PumpOnce();

            string clipErr;
            bool clipOk = SetMarkerClipboard(hwnd, marker, out clipErr);
            uint pixel = 0;
            bool pixOk = CaptureWindowPixel(hwnd, out pixel);

            TextUtil.WriteStatus(readyPath,
                "OK WINSTA=" + staName +
                " DESK=" + deskName +
                " DESKTOP=" + staName + "\\" + deskName +
                " CLIP=" + (clipOk ? "OK" : "FAIL") +
                " CLIP_ERR=" + clipErr +
                " PIXEL=0x" + pixel.ToString("X") +
                " PIXEL_OK=" + pixOk +
                " HWND=0x" + hwnd.ToInt64().ToString("X"));

            IntPtr shutdown = IntPtr.Zero;
            if (!string.IsNullOrEmpty(shutdownName))
            {
                shutdown = Native.OpenEvent(Native.SYNCHRONIZE, false, shutdownName);
            }
            Clock clock = new Clock();
            while (clock.Elapsed < timeoutMs)
            {
                PumpOnce();
                if (shutdown != IntPtr.Zero)
                {
                    uint w = Native.WaitForSingleObject(shutdown, 30);
                    if (w == Native.WAIT_OBJECT_0)
                    {
                        break;
                    }
                }
                else
                {
                    Thread.Sleep(30);
                }
            }
            Native.DestroyWindow(hwnd);
            return 0;
        }

        static IntPtr CreateFixtureWindow()
        {
            FixtureProcKeepAlive = new Native.WndProc(FixtureWndProc);
            Native.WNDCLASS wc = new Native.WNDCLASS();
            wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(FixtureProcKeepAlive);
            wc.hInstance = Native.GetModuleHandle(null);
            wc.hbrBackground = Native.CreateSolidBrush(Constants.FixtureColor);
            IntPtr className = Marshal.StringToHGlobalUni(Constants.FixtureClass);
            wc.lpszClassName = className;
            Native.RegisterClass(ref wc);
            IntPtr hwnd = Native.CreateWindowEx(
                0, Constants.FixtureClass, Constants.FixtureTitle,
                Native.WS_POPUP | Native.WS_VISIBLE,
                0, 0, 80, 80,
                IntPtr.Zero, IntPtr.Zero, wc.hInstance, IntPtr.Zero);
            return hwnd;
        }

        static IntPtr FixtureWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            if (msg == Native.WM_PAINT)
            {
                Native.PAINTSTRUCT ps;
                IntPtr hdc = Native.BeginPaint(hWnd, out ps);
                Native.RECT rc;
                Native.GetClientRect(hWnd, out rc);
                IntPtr brush = Native.CreateSolidBrush(Constants.FixtureColor);
                Native.FillRect(hdc, ref rc, brush);
                Native.DeleteObject(brush);
                Native.EndPaint(hWnd, ref ps);
                return IntPtr.Zero;
            }
            if (msg == Native.WM_DESTROY)
            {
                Native.PostQuitMessage(0);
                return IntPtr.Zero;
            }
            return Native.DefWindowProc(hWnd, msg, wParam, lParam);
        }

        static void PumpOnce()
        {
            Native.MSG msg;
            while (Native.PeekMessage(out msg, IntPtr.Zero, 0, 0, Native.PM_REMOVE))
            {
                Native.TranslateMessage(ref msg);
                Native.DispatchMessage(ref msg);
            }
        }

        static bool SetMarkerClipboard(IntPtr hwnd, string marker, out string err)
        {
            err = "";
            string sta;
            string desk;
            string reason = "";
            if (!Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out sta) ||
                !Native.TryGetUserObjectName(Native.GetThreadDesktop(Native.GetCurrentThreadId()), out desk) ||
                !FixtureGuard.TryAllow(sta, desk, out reason))
            {
                err = "guard:" + (string.IsNullOrEmpty(reason) ? "denied" : reason);
                return false;
            }
            FixtureGuard.ClipboardApiEntered++;
            if (!Native.OpenClipboard(hwnd))
            {
                err = "OpenClipboard win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (!Native.EmptyClipboard())
                {
                    err = "EmptyClipboard win32=" + Marshal.GetLastWin32Error();
                    return false;
                }
                byte[] bytes = Encoding.Unicode.GetBytes(marker + "\0");
                IntPtr h = Native.GlobalAlloc(Native.GMEM_MOVEABLE, new UIntPtr((uint)bytes.Length));
                if (h == IntPtr.Zero)
                {
                    err = "GlobalAlloc failed";
                    return false;
                }
                IntPtr p = Native.GlobalLock(h);
                Marshal.Copy(bytes, 0, p, bytes.Length);
                Native.GlobalUnlock(h);
                if (Native.SetClipboardData((uint)Native.CF_UNICODETEXT, h) == IntPtr.Zero)
                {
                    err = "SetClipboardData win32=" + Marshal.GetLastWin32Error();
                    Native.GlobalFree(h);
                    return false;
                }
                err = "ok";
                return true;
            }
            finally
            {
                Native.CloseClipboard();
            }
        }

        static bool CaptureWindowPixel(IntPtr hwnd, out uint pixel)
        {
            pixel = 0;
            string sta;
            string desk;
            string reason = "";
            if (!Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out sta) ||
                !Native.TryGetUserObjectName(Native.GetThreadDesktop(Native.GetCurrentThreadId()), out desk) ||
                !FixtureGuard.TryAllow(sta, desk, out reason))
            {
                return false;
            }
            return false;
        }

        static int ProbeUi(string[] args, bool spawnChild)
        {
            string statusPath = Args.Get(args, "--status");
            string marker = Args.Get(args, "--marker");
            string expectSta = Args.Get(args, "--expect-winsta");
            string fixtureSta = Args.Get(args, "--fixture-winsta");
            string fixtureDesk = Args.Get(args, "--fixture-desk");
            TextUtil.WriteStatus(statusPath, "PHASE=ui");

            string curSta;
            if (!Native.TryGetUserObjectName(Native.GetProcessWindowStation(), out curSta))
            {
                curSta = "unknown";
            }
            TextUtil.AppendStatus(statusPath, "CURRENT_WINSTA=" + curSta);
            string allowReason;
            if (!FixtureGuard.TryAllow(expectSta, fixtureDesk, out allowReason))
            {
                TextUtil.AppendStatus(statusPath, "REFUSED=" + allowReason +
                    " CLIPBOARD_API=" + FixtureGuard.ClipboardApiEntered +
                    " CAPTURE_API=" + FixtureGuard.CaptureApiEntered);
                return 2;
            }

            int clipReadWin = -1;
            string clipRead = "";
            bool clipReadOk = TryReadClipboard(expectSta, fixtureDesk, out clipRead, out clipReadWin);
            TextUtil.AppendStatus(statusPath, "CLIP_READ ok=" + clipReadOk + " win32=" + clipReadWin +
                " match=" + string.Equals(clipRead, marker, StringComparison.Ordinal) +
                " len=" + (clipRead == null ? 0 : clipRead.Length));

            int clipWriteWin = -1;
            bool clipWriteOk = TryWriteClipboard(expectSta, fixtureDesk, "NMZP-NAS-WRITE-" + TextUtil.NewNonce().Substring(0, 8), out clipWriteWin);
            TextUtil.AppendStatus(statusPath, "CLIP_WRITE ok=" + clipWriteOk + " win32=" + clipWriteWin);

            int openHostWin = -1;
            bool openHost = TryOpenWindowStation("WinSta0", Native.WINSTA_ENUMERATE | Native.WINSTA_ENUMDESKTOPS | Native.WINSTA_READSCREEN, out openHostWin);
            TextUtil.AppendStatus(statusPath, "OPEN_WINSTA0 ok=" + openHost + " win32=" + openHostWin + " captured=false");

            int openFixWin = -1;
            bool openFix = false;
            if (!string.IsNullOrEmpty(fixtureSta))
            {
                openFix = TryOpenWindowStation(fixtureSta, Native.WINSTA_ENUMERATE | Native.WINSTA_ENUMDESKTOPS | Native.WINSTA_READSCREEN, out openFixWin);
            }
            TextUtil.AppendStatus(statusPath, "OPEN_FIXTURE_WINSTA ok=" + openFix + " win32=" + openFixWin);

            TextUtil.AppendStatus(statusPath, "FIND_HWND=skipped_title_not_ownership");
            TextUtil.AppendStatus(statusPath, "GDI_WINDOW_BITBLT ok=False win32=-3 reason=owned_hwnd_unproven");
            int screenWin = -1;
            bool screenHandle = false;
            ProbeScreenAccess(expectSta, fixtureDesk, out screenHandle, out screenWin);
            TextUtil.AppendStatus(statusPath, "GDI_SCREEN_DC_HANDLE ok=" + screenHandle + " win32=" + screenWin +
                " screen_pixels_not_tested=True station=" + curSta);
            TextUtil.AppendStatus(statusPath, "GDI_SCREEN_DC_BITBLT ok=False win32=-3 reason=screen_pixels_not_tested");

            TextUtil.AppendStatus(statusPath, "DXGI=not_tested");
            TextUtil.AppendStatus(statusPath, "WGC=not_tested");

            if (spawnChild)
            {
                string self = Args.Get(args, "--self");
                if (string.IsNullOrEmpty(self))
                {
                    self = Assembly.GetExecutingAssembly().Location;
                }
                string childStatus = Args.Get(args, "--desc-status");
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = self;
                    psi.Arguments = TextUtil.BuildArguments(new string[]
                    {
                        "--probe", "ui-child",
                        "--status", childStatus,
                        "--marker", marker ?? "",
                        "--expect-winsta", expectSta ?? "",
                        "--fixture-winsta", fixtureSta ?? "",
                        "--fixture-desk", fixtureDesk ?? "",
                        "--dispatch-ticket", Args.Get(args, "--dispatch-ticket") ?? ""
                    });
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    Process child = Process.Start(psi);
                    if (child == null)
                    {
                        TextUtil.AppendStatus(statusPath, "SPAWN=FAIL start_returned_null");
                    }
                    else
                    {
                        TextUtil.AppendStatus(statusPath, "SPAWN=OK PID=" + child.Id);
                        if (!child.WaitForExit(Constants.DescendantWaitMs))
                        {
                            try { child.Kill(); }
                            catch { }
                            TextUtil.AppendStatus(statusPath, "DESCENDANT=TIMEOUT");
                        }
                        else
                        {
                            TextUtil.AppendStatus(statusPath, "DESCENDANT_EXIT=" + child.ExitCode);
                        }
                    }
                }
                catch (Exception ex)
                {
                    TextUtil.AppendStatus(statusPath, "SPAWN=FAIL " + TextUtil.Sanitize(ex.GetType().Name + " " + ex.Message));
                }
            }
            return 0;
        }

        static bool TryReadClipboard(string expectSta, string expectDesk, out string text, out int win32)
        {
            text = "";
            win32 = 0;
            string reason;
            if (!FixtureGuard.TryAllow(expectSta, expectDesk, out reason))
            {
                win32 = -2;
                return false;
            }
            FixtureGuard.ClipboardApiEntered++;
            if (!Native.OpenClipboard(IntPtr.Zero))
            {
                win32 = Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                IntPtr h = Native.GetClipboardData((uint)Native.CF_UNICODETEXT);
                if (h == IntPtr.Zero)
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                IntPtr p = Native.GlobalLock(h);
                if (p == IntPtr.Zero)
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                try
                {
                    text = Marshal.PtrToStringUni(p) ?? "";
                    return true;
                }
                finally
                {
                    Native.GlobalUnlock(h);
                }
            }
            finally
            {
                Native.CloseClipboard();
            }
        }

        static bool TryWriteClipboard(string expectSta, string expectDesk, string text, out int win32)
        {
            win32 = 0;
            string reason;
            if (!FixtureGuard.TryAllow(expectSta, expectDesk, out reason))
            {
                win32 = -2;
                return false;
            }
            FixtureGuard.ClipboardApiEntered++;
            if (!Native.OpenClipboard(IntPtr.Zero))
            {
                win32 = Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                if (!Native.EmptyClipboard())
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
                IntPtr h = Native.GlobalAlloc(Native.GMEM_MOVEABLE, new UIntPtr((uint)bytes.Length));
                if (h == IntPtr.Zero)
                {
                    win32 = Marshal.GetLastWin32Error();
                    return false;
                }
                IntPtr p = Native.GlobalLock(h);
                Marshal.Copy(bytes, 0, p, bytes.Length);
                Native.GlobalUnlock(h);
                if (Native.SetClipboardData((uint)Native.CF_UNICODETEXT, h) == IntPtr.Zero)
                {
                    win32 = Marshal.GetLastWin32Error();
                    Native.GlobalFree(h);
                    return false;
                }
                return true;
            }
            finally
            {
                Native.CloseClipboard();
            }
        }

        static bool TryOpenWindowStation(string name, uint access, out int win32)
        {
            IntPtr h = Native.OpenWindowStation(name, false, access);
            win32 = h == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            if (h != IntPtr.Zero)
            {
                Native.CloseWindowStation(h);
                return true;
            }
            return false;
        }

        static bool TryBitBltWindow(string expectSta, string expectDesk, IntPtr hwnd, out uint pixel, out int win32)
        {
            pixel = 0;
            win32 = -3;
            string reason;
            if (!FixtureGuard.TryAllow(expectSta, expectDesk, out reason))
            {
                win32 = -2;
                return false;
            }
            return false;
        }

        static bool ProbeScreenAccess(string expectSta, string expectDesk, out bool handleOk, out int win32)
        {
            handleOk = false;
            win32 = 0;
            string reason;
            if (!FixtureGuard.TryAllow(expectSta, expectDesk, out reason))
            {
                win32 = -2;
                return false;
            }
            FixtureGuard.CaptureApiEntered++;
            IntPtr src = Native.GetDC(IntPtr.Zero);
            if (src == IntPtr.Zero)
            {
                win32 = Marshal.GetLastWin32Error();
                return false;
            }
            Native.ReleaseDC(IntPtr.Zero, src);
            handleOk = true;
            return true;
        }
    }
}
