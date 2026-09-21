using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

// SCM owns this process. Only a virtual service account is accepted; never run Node as SYSTEM.
class ProbeService : ServiceBase {
    const string NameValue="NMZPProbe";
    static readonly string ProgramRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),NameValue);
    static readonly string DataRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),NameValue);
    static string Sid {get{return ((SecurityIdentifier)new NTAccount("NT SERVICE",NameValue).Translate(typeof(SecurityIdentifier))).Value;}}
    readonly string root, manifestHash;
    IntPtr job=IntPtr.Zero, process=IntPtr.Zero;
    Timer timer; int checking;
    ProbeService(string hash) {ServiceName=NameValue;CanStop=true;AutoLog=false;root=AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');manifestHash=hash;}
    static bool Trusted(string sid,bool mutable,string serviceSid) {return sid=="S-1-5-18"||sid=="S-1-5-32-544"||(mutable&&sid==serviceSid); }
    static void NoLinks(string path) {
        for(string p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p))if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new Exception("reparse_path");
    }
    static void Acl(string path,bool mutable,bool ancestor) {
        NoLinks(path);
        bool dir=Directory.Exists(path);
        FileSystemSecurity acl=dir?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
        ValidateAcl(acl,mutable,ancestor,Sid);
    }
    static void ValidateAcl(FileSystemSecurity acl,bool mutable,bool ancestor,string serviceSid) {
        string owner=acl.GetOwner(typeof(SecurityIdentifier)).Value;
        // TrustedInstaller may own OS ancestors; this exception never applies to our own tree.
        if(!ancestor&&!Trusted(owner,mutable,serviceSid))throw new Exception("untrusted_owner");
        FileSystemRights mask=ancestor?FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership:
            FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.WriteExtendedAttributes|FileSystemRights.WriteAttributes|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        if(mutable)mask=FileSystemRights.FullControl; // Confidentiality: reject even read grants to interactive users.
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
            if((rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;
            if(rule.AccessControlType==AccessControlType.Allow&&(rule.FileSystemRights&mask)!=0&&!Trusted(rule.IdentityReference.Value,mutable,serviceSid)) {
                // Windows servicing authority is permitted on ancestors only.
                if(ancestor&&rule.IdentityReference.Value=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")continue;
                throw new Exception("untrusted_write_acl");
            }
        }
    }
    static string Hash(string path) {using(var sha=SHA256.Create())using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){return BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();}}
    internal static bool SafeRelative(string p) {return Regex.IsMatch(p,@"^[A-Za-z0-9_./-]+$")&&!p.StartsWith("/")&&!p.Contains("//")&&Array.TrueForAll(p.Split('/'),x=>x!="."&&x!=".."&&x.Length>0);}
    internal static Dictionary<string,string> Manifest(string text) {
        if(text.Length>1024*1024)throw new Exception("manifest_limit");
        var files=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach(var line in text.Split(new[]{'\n'},StringSplitOptions.RemoveEmptyEntries)) {
            var p=line.TrimEnd('\r').Split('\t');
            if(p.Length!=2||!Regex.IsMatch(p[0],"^[a-f0-9]{64}$")||!SafeRelative(p[1])||files.ContainsKey(p[1])||files.Count>=4096)throw new Exception("manifest_invalid");
            files.Add(p[1],p[0]);
        }
        if(!files.ContainsKey("node.exe")||!files.ContainsKey("ProbeService.exe")||!files.ContainsKey("runtime/probe-service-main.ts"))throw new Exception("manifest_incomplete");
        return files;
    }
    static void Walk(string dir,List<string> files,int depth) {
        if(depth>12||files.Count>4096)throw new Exception("tree_limit");
        foreach(string p in Directory.GetFileSystemEntries(dir)) {NoLinks(p);if(Directory.Exists(p))Walk(p,files,depth+1);else files.Add(p);}
    }
    void Validate() {
        if(!Regex.IsMatch(manifestHash,"^[a-f0-9]{64}$")||!root.StartsWith(ProgramRoot+"\\releases\\",StringComparison.OrdinalIgnoreCase))throw new Exception("service_location");
        if(WindowsIdentity.GetCurrent().User.Value!=Sid)throw new Exception("service_account_required");
        for(string p=root;p!=null;p=Path.GetDirectoryName(p))Acl(p,false,!p.StartsWith(ProgramRoot,StringComparison.OrdinalIgnoreCase));
        for(string p=DataRoot;p!=null;p=Path.GetDirectoryName(p))Acl(p,false,p!=DataRoot);
        string home=Path.Combine(DataRoot,"private");Acl(home,true,false);Acl(Path.Combine(home,"probe-private.pem"),true,false);
        Acl(Path.Combine(home,".nmzp"),true,false);Acl(Path.Combine(home,".nmzp","credentials.json"),true,false);
        string manifest=Path.Combine(root,"manifest.tsv");Acl(manifest,false,false);if(Hash(manifest)!=manifestHash)throw new Exception("manifest_hash");
        var expected=Manifest(File.ReadAllText(manifest));var actual=new List<string>();Walk(root,actual,0);
        if(actual.Count!=expected.Count+1)throw new Exception("unexpected_files");
        foreach(string file in actual) {
            for(string p=file;p!=root;p=Path.GetDirectoryName(p))Acl(p,false,false);
            string rel=file.Substring(root.Length+1).Replace('\\','/');if(rel=="manifest.tsv")continue;
            string hash;if(!expected.TryGetValue(rel,out hash)||Hash(file)!=hash)throw new Exception("file_hash");
        }
    }
    protected override void OnStart(string[] args) {
        try {RequestAdditionalTime(60000);Validate();Launch();timer=new Timer(Check,null,30000,30000);}catch{Cleanup();throw new Exception("probe_service_start_rejected");}
    }
    void Check(object unused) {
        if(Interlocked.Exchange(ref checking,1)!=0)return;
        try {Validate();uint code;if(!GetExitCodeProcess(process,out code)||code!=259)throw new Exception("child_exit");}
        catch {ExitCode=1;Stop();}finally{Interlocked.Exchange(ref checking,0);}
    }
    protected override void OnStop(){if(timer!=null)timer.Dispose();Cleanup();}
    void Cleanup(){var j=Interlocked.Exchange(ref job,IntPtr.Zero);if(j!=IntPtr.Zero)CloseHandle(j);var p=Interlocked.Exchange(ref process,IntPtr.Zero);if(p!=IntPtr.Zero)CloseHandle(p);}
    void Launch() {
        string home=Path.Combine(DataRoot,"private"),temp=Path.Combine(home,"tmp");Acl(temp,true,false);
        job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Exception("job_create");
        var limits=new JOB_EXTENDED();limits.BasicLimitInformation.LimitFlags=0x2000; // KILL_ON_JOB_CLOSE, no breakaway
        int len=Marshal.SizeOf(limits);IntPtr ptr=Marshal.AllocHGlobal(len);
        try {Marshal.StructureToPtr(limits,ptr,false);if(!SetInformationJobObject(job,9,ptr,(uint)len))throw new Exception("job_limit");}finally{Marshal.FreeHGlobal(ptr);}
        string win=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        // Allowlist environment; no NODE_OPTIONS, NODE_PATH, user PATH, npm settings or profile startup.
        var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase){{"SystemRoot",win},{"WINDIR",win},{"PATH",Path.Combine(win,"System32")},{"TEMP",temp},{"TMP",temp},{"USERPROFILE",home},{"HOME",home},{"NMZP_HOME",home},{"APPDATA",Path.Combine(home,"AppData","Roaming")},{"LOCALAPPDATA",Path.Combine(home,"AppData","Local")},{"ProgramData",Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}};
        var eb=new StringBuilder();foreach(var pair in env)eb.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');eb.Append('\0');
        var si=new STARTUPINFO();si.cb=Marshal.SizeOf(si);PROCESS_INFORMATION pi;IntPtr environment=Marshal.StringToHGlobalUni(eb.ToString());
        string exe=Path.Combine(root,"node.exe"),entry=Path.Combine(root,"runtime","probe-service-main.ts"),mailbox=Path.Combine(DataRoot,"public","discovery.json");
        try {
            if(!CreateProcess(exe,new StringBuilder(Quote(exe)+" --experimental-strip-types "+Quote(entry)+" "+Quote(home)+" "+Quote(mailbox)),IntPtr.Zero,IntPtr.Zero,false,0x08000404,environment,root,ref si,out pi))throw new Exception("child_create");
        }finally{Marshal.FreeHGlobal(environment);}
        process=pi.hProcess;
        try {if(!AssignProcessToJobObject(job,process)||ResumeThread(pi.hThread)==0xffffffff){TerminateProcess(process,1);throw new Exception("job_assign");}}finally{CloseHandle(pi.hThread);}
    }
    internal static string Quote(string s){if(s.Contains("\"")||s.Contains("\0")||s.EndsWith("\\"))throw new Exception("argument_invalid");return "\""+s+"\"";}
    static void Main(string[] args) {
        if(args.Length==1&&args[0]=="--self-test") {SelfTest();return;}
        if(args.Length!=2||args[0]!="--service")throw new Exception("SCM_service_only");
        ServiceBase.Run(new ProbeService(args[1]));
    }
    static void SelfTest() {
        foreach(string bad in new[]{"../node.exe","C:/node.exe","a//b","a/./b","a/../b","a:stream","/file","a\\b"})if(SafeRelative(bad))throw new Exception("unsafe_path_accepted");
        string h=new string('a',64),m=h+"\tnode.exe\n"+h+"\tProbeService.exe\n"+h+"\truntime/probe-service-main.ts\n";
        if(Manifest(m).Count!=3)throw new Exception("manifest_parse");bool rejected=false;try{Manifest(m+h+"\tNODE.EXE\n");}catch{rejected=true;}if(!rejected)throw new Exception("duplicate_accepted");
        rejected=false;try{Quote("a\"b");}catch{rejected=true;}if(!rejected)throw new Exception("quote_accepted");
        string fixtureSid="S-1-5-80-1-2-3-4-5";
        var acl=new DirectorySecurity();acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-544"),FileSystemRights.FullControl,AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(fixtureSid),FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        ValidateAcl(acl,false,false,fixtureSid);ValidateAcl(acl,true,false,fixtureSid);
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),FileSystemRights.Read,AccessControlType.Allow));
        ValidateAcl(acl,false,false,fixtureSid);rejected=false;try{ValidateAcl(acl,true,false,fixtureSid);}catch{rejected=true;}if(!rejected)throw new Exception("private_read_leak_accepted");
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),FileSystemRights.WriteData,AccessControlType.Allow));
        rejected=false;try{ValidateAcl(acl,false,false,fixtureSid);}catch{rejected=true;}if(!rejected)throw new Exception("program_write_accepted");
        Console.WriteLine("PASS: synthetic ACL rejects user key reads and program writes;  traversal, ADS, duplicate/case collision, manifest required files, argument quoting. No SCM/ACL/process changes performed.");
    }
    [StructLayout(LayoutKind.Sequential)] struct JOB_BASIC {public long PerProcessUserTimeLimit,PerJobUserTimeLimit;public uint LimitFlags;public UIntPtr MinimumWorkingSetSize,MaximumWorkingSetSize;public uint ActiveProcessLimit;public UIntPtr Affinity;public uint PriorityClass,SchedulingClass;}
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS {public ulong a,b,c,d,e,f;}
    [StructLayout(LayoutKind.Sequential)] struct JOB_EXTENDED {public JOB_BASIC BasicLimitInformation;public IO_COUNTERS IoInfo;public UIntPtr ProcessMemoryLimit,JobMemoryLimit,PeakProcessMemoryUsed,PeakJobMemoryUsed;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO {public int cb;public string lpReserved,lpDesktop,lpTitle;public uint dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags;public short wShowWindow,cbReserved2;public IntPtr lpReserved2,hStdInput,hStdOutput,hStdError;}
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {public IntPtr hProcess,hThread;public uint dwProcessId,dwThreadId;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref STARTUPINFO si,out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr sa,string name);
    [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job,int cls,IntPtr info,uint len);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr proc);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
}
