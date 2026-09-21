using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace NativeAgentSandbox
{
    // Versioned, bounded contract. All files are staged while impersonating the limited user.
    // No arbitrary configuration text, parent HOME, approval bypass, or caller proof booleans.
    internal sealed class GrokSessionSpec
    {
        public string Model, Token, Hash, Prompt, Pipe, ControlToken, Mode;
        public JVal Files, Tools;
        public static bool SafeRelative(string p)
        {
            if (string.IsNullOrEmpty(p) || p.Length > 180 || p.IndexOf('\\') >= 0 || p.IndexOfAny(new char[]{'\r','\n','\0'})>=0) return false;
            foreach (string part in p.Split('/')) {
                if (!Regex.IsMatch(part, "^[a-zA-Z0-9_.-]+$") || part == "." || part == ".." || part.EndsWith(".") ||
                    Regex.IsMatch(part, "^(con|prn|aux|nul|com[0-9]|lpt[0-9])([.]|$)", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(part, "^([.]env([.]|$)|[.]git$|[.]grok$|[.]ssh$|[.]codex$)", RegexOptions.IgnoreCase)) return false;
            }
            return true;
        }
        static string Required(JVal o, string key, string pattern) {
            JVal v=o.Get(key); string s=v==null?"":v.AsString("");
            if (v==null || v.Kind!="str" || !Regex.IsMatch(s,pattern.Replace("$","\\z"))) throw new InvalidOperationException("invalid grok session " + key);
            return s;
        }
        public static GrokSessionSpec Parse(JVal o) {
            if (o==null || o.Kind!="obj") throw new InvalidOperationException("grok_session object required");
            HashSet<string> keys=new HashSet<string>(new string[]{"model","session_token","executable_sha256","prompt","pipe","control_token","files","tools","mode"});
            foreach(string k in o.Map.Keys) if(!keys.Contains(k)) throw new InvalidOperationException("unknown grok session field");
            GrokSessionSpec s=new GrokSessionSpec();
            s.Model=Required(o,"model","^[a-zA-Z0-9_.:/-]{1,128}$");
            s.Token=Required(o,"session_token","^[a-f0-9]{64}$");
            s.Hash=Required(o,"executable_sha256","^[a-fA-F0-9]{64}$");
            s.Pipe=Required(o,"pipe","^nmzp-owned-[a-f0-9]{64}$");
            s.ControlToken=Required(o,"control_token","^[a-f0-9]{64}$");
            s.Prompt=o.Get("prompt")==null?"":o.Get("prompt").AsString("");
            s.Mode=o.Get("mode")==null?"acp":Required(o,"mode","^(acp|headless)$");
            if(s.Prompt.Length>16384 || s.Prompt.IndexOf('\0')>=0) throw new InvalidOperationException("prompt limit");
            s.Files=o.Get("files"); s.Tools=o.Get("tools");
            if(s.Files==null || s.Files.Kind!="arr" || s.Files.Items.Count>128) throw new InvalidOperationException("workspace file limit");
            if(s.Tools==null || s.Tools.Kind!="arr" || s.Tools.Items.Count>8) throw new InvalidOperationException("tool limit");
            int total=0; HashSet<string> seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(JVal f in s.Files.Items) {
                string p=Required(f,"path","^.{1,180}$");
                if(!SafeRelative(p) || !seen.Add(p) || f.Map.Count!=2) throw new InvalidOperationException("workspace path refused");
                byte[] b=Convert.FromBase64String(Required(f,"base64","^[a-zA-Z0-9+/=]*$"));
                total+=b.Length; if(total>131072) throw new InvalidOperationException("workspace byte limit");
            }
            seen.Clear(); seen.Add("grok.exe");
            foreach(JVal t in s.Tools.Items) {
                string n=Required(t,"name","^[a-zA-Z0-9_-]+[.]exe$");
                if(!SafeRelative(n) || !seen.Add(n) || t.Map.Count!=3) throw new InvalidOperationException("tool name refused");
                Required(t,"sha256","^[a-fA-F0-9]{64}$"); Required(t,"path","^.{1,240}$");
            }
            return s;
        }
        public string Toml(int port) {
            return "[models]\ndefault = \"nmzp-protected\"\nweb_search = \"nmzp-protected\"\nsession_summary = \"nmzp-protected\"\nimage_description = \"nmzp-protected\"\nallowed_models = [\"nmzp-protected\"]\n"+
                "[model.nmzp-protected]\nmodel = \""+Model+"\"\nname = \"NMZP Protected Session\"\nbase_url = \"http://127.0.0.1:"+port+"/v1\"\napi_key = \""+Token+"\"\napi_backend = \"chat_completions\"\nmax_retries = 0\ninference_idle_timeout_secs = 20\nstream_tool_calls = false\n"+
                "[session]\nload_envrc = false\n[ui]\ndefault_selected_permission = \"allow_once\"\nremember_tool_approvals = false\n";
        }
        public void Stage(LaunchRequest req, string home) {
            if(SessionFiles.HasReparseInAncestry(home)) throw new InvalidOperationException("profile reparse refused");
            if(!string.Equals(PrivilegedInit.FileSha256(req.Executable),Hash,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("grok hash mismatch");
            string workspace=Path.Combine(home,"workspace"), app=Path.Combine(home,"app");
            foreach(JVal f in Files.Items) {
                string dest=Path.Combine(workspace,f.Get("path").AsString("").Replace('/',Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(dest));
                using(FileStream stream=new FileStream(dest,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    byte[] b=Convert.FromBase64String(f.Get("base64").AsString("")); stream.Write(b,0,b.Length);
                }
            }
            foreach(JVal t in Tools.Items) {
                string src=t.Get("path").AsString(""), dest=Path.Combine(app,t.Get("name").AsString(""));
                if(SessionFiles.HasReparseInAncestry(src)) throw new InvalidOperationException("tool reparse refused");
                File.Copy(src,dest,false);
                if(!string.Equals(PrivilegedInit.FileSha256(dest),t.Get("sha256").AsString(""),StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("tool hash mismatch");
            }
            File.WriteAllText(Path.Combine(home,"config.toml"),Toml(req.GatewayPort),new UTF8Encoding(false));
            req.WorkingDirectory=workspace;
            List<string> args=new List<string>(new string[]{"--leader-socket",Path.Combine(home,"leader-"+TextUtil.NewNonce()+".sock"),"--cwd",workspace,"--model","nmzp-protected","--disable-web-search","--no-subagents","--permission-mode","default"});
            if(Mode=="acp") { args.Add("agent"); args.Add("stdio"); }
            else if(Prompt.Length>0) { string file=Path.Combine(home,"initial-prompt.txt"); File.WriteAllText(file,Prompt,new UTF8Encoding(false)); args.Add("--prompt-file"); args.Add(file); }
            else throw new InvalidOperationException("headless prompt required");
            req.Arguments=args.ToArray();
            req.ExtraEnv["GROK_DISABLE_AUTOUPDATER"]="1";
            req.ExtraEnv["GROK_SANDBOX_AUTO_ALLOW_BASH"]="0";
            req.ExtraEnv["GROK_REMEMBER_TOOL_APPROVALS"]="false";
        }
    }

    internal sealed class ControllerChannel : IDisposable
    {
        NamedPipeClientStream pipe; StreamReader reader; StreamWriter writer;
        readonly Queue<string> output=new Queue<string>(); readonly object gate=new object();
        volatile bool stopped; public volatile bool Failed; ChildSession child;
        volatile bool writing; long writeStarted;
        int outPos,errPos; Thread inputThread,outputThread;
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
        public static ControllerChannel Connect(LaunchRequest req) {
            ControllerLifetime held; string error;
            if(!ControllerLifetime.TryOpen(req.ControllerPid,req.ControllerCreationTime,0,out held,out error)) throw new InvalidOperationException("controller identity refused");
            using(held) {
                ControllerChannel c=new ControllerChannel();
                try {
                    c.pipe=new NamedPipeClientStream(".",req.Grok.Pipe,PipeDirection.InOut,PipeOptions.Asynchronous);
                    c.pipe.Connect(5000); uint server;
                    if(!GetNamedPipeServerProcessId(c.pipe.SafePipeHandle.DangerousGetHandle(),out server) || server!=(uint)req.ControllerPid || !held.IsAlive()) throw new InvalidOperationException("pipe server identity refused");
                    c.reader=new StreamReader(c.pipe,new UTF8Encoding(false,true)); c.writer=new StreamWriter(c.pipe,new UTF8Encoding(false)); c.writer.AutoFlush=true;
                    JVal hello=JVal.Obj(); hello.Map["type"]=JVal.Str("hello"); hello.Map["version"]=JVal.Num(1); hello.Map["token"]=JVal.Str(req.Grok.ControlToken);
                    // Bound startup write; a stalled controller is terminated via the channel budget.
                    c.outputThread=new Thread(c.WriteLoop); c.outputThread.IsBackground=true; c.outputThread.Start(); c.Send(hello);
                    bool accepted=false; Thread handshake=new Thread(delegate() { try { JVal reply=Json.Parse(c.ReadBounded()); accepted=reply.Kind=="obj" && reply.Map.Count==1 && reply.Get("type").AsString("")=="start"; } catch {} });
                    handshake.IsBackground=true; handshake.Start();
                    if(!handshake.Join(5000) || !accepted || c.Failed) throw new InvalidOperationException("controller handshake timeout");
                    return c;
                } catch { c.Dispose(); throw; }
            }
        }
        public void Attach(ChildSession s) {
            child=s; inputThread=new Thread(ReadLoop); inputThread.IsBackground=true; inputThread.Start();
            JVal ready=JVal.Obj(); ready.Map["type"]=JVal.Str("running"); ready.Map["pid"]=JVal.Num(s.Pid); ready.Map["workspace"]=JVal.Str(s.StagingWorkspace); Send(ready);
        }
        void WriteLoop() {
            try { while(!stopped) { string line=null; lock(gate) { if(output.Count>0) { line=output.Dequeue(); Interlocked.Exchange(ref writeStarted,DateTime.UtcNow.Ticks); writing=true; } else Monitor.Wait(gate,100); }
                if(line!=null) { writer.WriteLine(line); writing=false; }
            }} catch { Failed=true; }
        }
        string ReadBounded() { StringBuilder b=new StringBuilder(); for(int i=0;i<8192;i++) { int c=reader.Read(); if(c<0) throw new IOException(); if(c=='\n') return b.ToString(); b.Append((char)c); } throw new IOException(); }
        void ReadLoop() {
            try { while(!stopped) {
                JVal m=Json.Parse(ReadBounded()); string type=m.Get("type").AsString("");
                if(type=="stop") { Failed=true; return; }
                if(type=="stdin_eof" && m.Map.Count==1) { Native.CloseHandle(child.StdinWrite); child.StdinWrite=IntPtr.Zero; return; }
                if(type!="stdin" || m.Map.Count!=2) throw new IOException();
                byte[] b=Convert.FromBase64String(m.Get("base64").AsString("")); if(b.Length>4096) throw new IOException();
                uint n; if(!Native.WriteFile(child.StdinWrite,b,(uint)b.Length,out n,IntPtr.Zero) || n!=b.Length) throw new IOException();
            }} catch { if(!stopped) Failed=true; }
        }
        public void Send(JVal value) {
            string line=Json.Stringify(value); if(line.Length>200000) { Failed=true; return; }
            lock(gate) { if(output.Count>=64) { Failed=true; return; } output.Enqueue(line); Monitor.Pulse(gate); }
        }
        void SendText(string stream,StringBuilder buf,ref int pos) {
            while(pos<buf.Length) { int n=Math.Min(2048,buf.Length-pos); JVal m=JVal.Obj(); m.Map["type"]=JVal.Str(stream); m.Map["text"]=JVal.Str(buf.ToString(pos,n)); pos+=n; Send(m); }
        }
        public void Pump() {
            if(writing && DateTime.UtcNow.Ticks-Interlocked.Read(ref writeStarted)>TimeSpan.FromSeconds(5).Ticks) Failed=true;
            if(child!=null) { SendText("stdout",child.OutBuf,ref outPos); SendText("stderr",child.ErrBuf,ref errPos); if(child.OutTruncated || child.ErrTruncated) Failed=true; }
        }
        public void Flush() { DateTime end=DateTime.UtcNow.AddSeconds(3); while(DateTime.UtcNow<end) { lock(gate) { if(output.Count==0 && !writing) return; } Thread.Sleep(10); } Failed=true; }
        public void Dispose() { stopped=true; try { if(pipe!=null) pipe.Dispose(); } catch {} }
    }

    internal static class GrokWorkspace
    {
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public uint attrs; public Native.FILETIME created,accessed,written; public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out Info info);
        public static void Capture(LaunchRequest req,ChildSession session,LaunchResult result) {
            if(!session.WaitJobIdle(3000) || req.Channel.Failed) { result.Ok=false; result.ErrorCode="workspace_tree_not_idle"; return; }
            if(!Native.ImpersonateLoggedOnUser(req.ImpersonationToken)) { result.Ok=false; result.ErrorCode="workspace_impersonation"; return; }
            try {
                JVal files=JVal.Arr(); int total=0;
                Walk(session.StagingWorkspace,"",files,ref total);
                JVal msg=JVal.Obj(); msg.Map["type"]=JVal.Str("workspace"); msg.Map["files"]=files; req.Channel.Send(msg);
                result.Extra.Map["workspace_exported_files"]=JVal.Num(files.Items.Count);
            } catch { result.Ok=false; result.ErrorCode="workspace_export_refused"; }
            finally { SessionFiles.MustRevert(); }
        }
        static void Walk(string root,string rel,JVal files,ref int total) {
            string dir=Path.Combine(root,rel.Replace('/',Path.DirectorySeparatorChar));
            if(SessionFiles.HasReparseInAncestry(dir)) throw new IOException();
            foreach(string p in Directory.GetFileSystemEntries(dir)) {
                string name=(rel.Length==0?"":rel+"/")+Path.GetFileName(p);
                if(!GrokSessionSpec.SafeRelative(name) || SessionFiles.HasReparseInAncestry(p)) throw new IOException();
                if(Directory.Exists(p)) { if(name.Split('/').Length>16) throw new IOException(); Walk(root,name,files,ref total); continue; }
                if(files.Items.Count>=128) throw new IOException();
                using(FileStream f=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.None)) {
                    Info info; if(!GetFileInformationByHandle(f.SafeFileHandle.DangerousGetHandle(),out info) || info.links!=1 || (info.attrs & (uint)FileAttributes.ReparsePoint)!=0) throw new IOException();
                    if(f.Length>131072 || total+f.Length>131072) throw new IOException();
                    byte[] bytes=new byte[(int)f.Length]; int pos=0,n; while(pos<bytes.Length && (n=f.Read(bytes,pos,bytes.Length-pos))>0) pos+=n; if(pos!=bytes.Length) throw new IOException(); total+=bytes.Length;
                    JVal row=JVal.Obj(); row.Map["path"]=JVal.Str(name); row.Map["base64"]=JVal.Str(Convert.ToBase64String(bytes)); files.Items.Add(row);
                }
            }
        }
    }
    internal static class ControllerIdentity
    {
        public static int Run(string value) {
            int pid; if(!int.TryParse(value,out pid) || pid<=0) return 2;
            IntPtr h=Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION,false,pid);
            long time; string error;
            try { if(!ControllerLifetime.TryReadCreationTime(h,out time,out error)) return 3; }
            finally { if(h!=IntPtr.Zero) Native.CloseHandle(h); }
            ControllerLifetime held;
            if(!ControllerLifetime.TryOpen(pid,time,0,out held,out error)) { Console.WriteLine("{\"ordinary\":false}"); return 3; }
            using(held) { JVal o=JVal.Obj(); o.Map["ordinary"]=JVal.Bool(true); o.Map["pid"]=JVal.Num(pid); o.Map["creationTime"]=JVal.Str(time.ToString(System.Globalization.CultureInfo.InvariantCulture)); o.Map["ownedWfpBuildEnabled"]=JVal.Bool(NetworkFilterBroker.RealApplyEnabledThisBuild); Console.WriteLine(Json.Stringify(o)); }
            return 0;
        }
    }
}
