using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NativeAgentSandbox
{
    internal sealed class DispatchTicket : IDisposable
    {
        public string Path;
        public string EventName;
        public string Nonce;
        public IntPtr EventHandle;
        public string Station;
        public string Desk;
        bool disposed;

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (EventHandle != IntPtr.Zero)
            {
                Native.CloseHandle(EventHandle);
                EventHandle = IntPtr.Zero;
            }
        }
    }

    internal static class InternalDispatch
    {
        const int TicketMaxBytes = 2048;

        public static string EventNameFromNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce) || nonce.Length < 16)
            {
                return "";
            }
            return "Local\\nmzp.agent." + nonce.Substring(0, 16) + ".disp";
        }

        public static bool TryCreate(string dir, string modes, string station, string desk, out DispatchTicket ticket, out string error)
        {
            ticket = null;
            error = "";
            if (string.IsNullOrEmpty(dir))
            {
                error = "dispatch dir required";
                return false;
            }
            if (SessionFiles.HasReparseInAncestry(dir))
            {
                error = "dispatch_dir_reparse";
                return false;
            }
            Directory.CreateDirectory(dir);
            if (SessionFiles.HasReparseInAncestry(dir))
            {
                error = "dispatch_dir_reparse_after_create";
                return false;
            }
            if (!string.IsNullOrEmpty(station) && Native.IsWinSta0Name(station))
            {
                error = "dispatch_station_winsta0";
                return false;
            }
            string nonce = TextUtil.NewNonce();
            if (!IsHex(nonce, 32))
            {
                error = "nonce";
                return false;
            }
            string evName = EventNameFromNonce(nonce);
            IntPtr sd = IntPtr.Zero;
            IntPtr psa = IntPtr.Zero;
            string user = CurrentUserSid();
            if (string.IsNullOrEmpty(user))
            {
                error = "no current user sid";
                return false;
            }
            string sddl = "D:P(A;;0x1F0003;;;" + user + ")(A;;GA;;;SY)";
            if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, Native.SDDL_REVISION_1, out sd, IntPtr.Zero) ||
                sd == IntPtr.Zero)
            {
                error = "event_sddl win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            try
            {
                Native.SECURITY_ATTRIBUTES sa = new Native.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(Native.SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = 0;
                psa = Marshal.AllocHGlobal(sa.nLength);
                Marshal.StructureToPtr(sa, psa, false);
                IntPtr ev = Native.CreateEvent(psa, true, true, evName);
                int err = Marshal.GetLastWin32Error();
                if (ev == IntPtr.Zero || err == Native.ERROR_ALREADY_EXISTS)
                {
                    if (ev != IntPtr.Zero)
                    {
                        Native.CloseHandle(ev);
                    }
                    error = "CreateEvent dispatch win32=" + err;
                    return false;
                }
                string path = Path.Combine(dir, "dispatch." + nonce.Substring(0, 8) + ".txt");
                StringBuilder sb = new StringBuilder();
                sb.Append("v=1\n");
                sb.Append("nonce=").Append(nonce).Append('\n');
                sb.Append("event=").Append(evName).Append('\n');
                sb.Append("modes=").Append(modes ?? "").Append('\n');
                sb.Append("station=").Append(station ?? "").Append('\n');
                sb.Append("desk=").Append(desk ?? "").Append('\n');
                sb.Append("exp=").Append(DateTime.UtcNow.AddMinutes(10).Ticks.ToString()).Append('\n');
                try
                {
                    File.WriteAllText(path, sb.ToString(), Encoding.ASCII);
                }
                catch (Exception ex)
                {
                    Native.CloseHandle(ev);
                    error = TextUtil.Sanitize(ex.Message);
                    return false;
                }
                ticket = new DispatchTicket();
                ticket.Path = path;
                ticket.EventName = evName;
                ticket.Nonce = nonce;
                ticket.EventHandle = ev;
                ticket.Station = station ?? "";
                ticket.Desk = desk ?? "";
                return true;
            }
            finally
            {
                if (psa != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(psa);
                }
                if (sd != IntPtr.Zero)
                {
                    Native.LocalFree(sd);
                }
            }
        }

        public static bool TryValidate(string ticketPath, string requestedMode, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(ticketPath))
            {
                error = "dispatch_ticket_missing";
                return false;
            }
            if (SessionFiles.HasReparseInAncestry(ticketPath))
            {
                error = "dispatch_reparse";
                return false;
            }
            FileInfo fi;
            try
            {
                fi = new FileInfo(ticketPath);
            }
            catch
            {
                error = "dispatch_ticket_missing";
                return false;
            }
            if (!fi.Exists || fi.Length <= 0 || fi.Length > TicketMaxBytes)
            {
                error = "dispatch_ticket_missing";
                return false;
            }
            string text;
            try
            {
                text = File.ReadAllText(ticketPath, Encoding.ASCII);
            }
            catch
            {
                error = "dispatch_ticket_unreadable";
                return false;
            }
            if (text.Length > TicketMaxBytes)
            {
                error = "dispatch_ticket_too_large";
                return false;
            }
            string v = Field(text, "v");
            string nonce = Field(text, "nonce");
            string evName = Field(text, "event");
            string modes = Field(text, "modes");
            string station = Field(text, "station");
            string desk = Field(text, "desk");
            string expS = Field(text, "exp");
            if (v != "1")
            {
                error = "dispatch_version";
                return false;
            }
            if (!IsHex(nonce, 32))
            {
                error = "dispatch_nonce";
                return false;
            }
            string derived = EventNameFromNonce(nonce);
            if (string.IsNullOrEmpty(evName) || !string.Equals(evName, derived, StringComparison.Ordinal))
            {
                error = "dispatch_event_binding";
                return false;
            }
            string fileName = fi.Name;
            if (fileName.IndexOf("dispatch." + nonce.Substring(0, 8), StringComparison.OrdinalIgnoreCase) < 0)
            {
                error = "dispatch_filename_binding";
                return false;
            }
            long exp;
            if (!long.TryParse(expS, out exp) || exp < DateTime.UtcNow.Ticks)
            {
                error = "dispatch_expired";
                return false;
            }
            if (string.IsNullOrEmpty(requestedMode) || !ModeAllowed(requestedMode) ||
                ("," + modes + ",").IndexOf("," + requestedMode + ",", StringComparison.OrdinalIgnoreCase) < 0)
            {
                error = "dispatch_mode_not_allowed";
                return false;
            }
            IntPtr opened = Native.OpenEvent(Native.EVENT_MODIFY_STATE | Native.SYNCHRONIZE, false, evName);
            if (opened == IntPtr.Zero)
            {
                error = "dispatch_event_open_win32=" + Marshal.GetLastWin32Error();
                return false;
            }
            Native.CloseHandle(opened);
            if (NeedsPrivateStation(requestedMode))
            {
                if (string.IsNullOrEmpty(station) || string.IsNullOrEmpty(desk) || Native.IsWinSta0Name(station) ||
                    !StationNameOk(station) || !DeskNameOk(desk))
                {
                    error = "dispatch_station_not_private";
                    return false;
                }
            }
            return true;
        }

        static bool NeedsPrivateStation(string mode)
        {
            return string.Equals(mode, "ui", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "ui-child", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "fixture-owner", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "winsta-holder", StringComparison.OrdinalIgnoreCase);
        }

        static bool ModeAllowed(string mode)
        {
            return string.Equals(mode, "ui", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "ui-child", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "fixture-owner", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "winsta-holder", StringComparison.OrdinalIgnoreCase);
        }

        static bool StationNameOk(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 64 || Native.IsWinSta0Name(name))
            {
                return false;
            }
            if (!name.StartsWith("nmzpsta", StringComparison.Ordinal))
            {
                return false;
            }
            for (int i = 7; i < name.Length; i++)
            {
                char c = name[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }
            return name.Length > 7;
        }

        static bool DeskNameOk(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 64)
            {
                return false;
            }
            if (!name.StartsWith("nmzpdesk", StringComparison.Ordinal))
            {
                return false;
            }
            for (int i = 8; i < name.Length; i++)
            {
                char c = name[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }
            return name.Length > 8;
        }

        static bool IsHex(string s, int len)
        {
            if (string.IsNullOrEmpty(s) || s.Length != len)
            {
                return false;
            }
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }
            return true;
        }

        static string CurrentUserSid()
        {
            try
            {
                System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (id != null && id.User != null)
                {
                    return id.User.Value;
                }
            }
            catch
            {
            }
            return "";
        }

        static string Field(string text, string key)
        {
            string prefix = key + "=";
            string[] lines = text.Replace("\r", "").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith(prefix, StringComparison.Ordinal))
                {
                    return lines[i].Substring(prefix.Length);
                }
            }
            return "";
        }
    }
}
