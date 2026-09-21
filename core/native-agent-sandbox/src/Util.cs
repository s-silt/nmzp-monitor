using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NativeAgentSandbox
{
    internal static class Args
    {
        public static bool HasFlag(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                if (args[i].StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public static string Get(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length)
                    {
                        return args[i + 1];
                    }
                    return "";
                }
                if (args[i].StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                {
                    return args[i].Substring(name.Length + 1);
                }
            }
            return "";
        }

        public static int GetInt(string[] args, string name, int fallback)
        {
            int v;
            if (int.TryParse(Args.Get(args, name), out v))
            {
                return v;
            }
            return fallback;
        }
    }

    internal static class TextUtil
    {
        public static string NewNonce()
        {
            byte[] b = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(b);
            }
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < b.Length; i++)
            {
                sb.Append(b[i].ToString("x2"));
            }
            return sb.ToString();
        }

        public static string Sanitize(string s)
        {
            if (s == null)
            {
                return "";
            }
            string t = s.Replace("\r", " ").Replace("\n", " ");
            if (t.Length > 400)
            {
                t = t.Substring(0, 400);
            }
            return t;
        }

        public static string OneLine(string s)
        {
            if (s == null)
            {
                return "";
            }
            return s.Replace("\r", " ").Replace("\n", " ").Trim();
        }

        public static bool ContainsToken(string text, string token)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token))
            {
                return false;
            }
            return text.IndexOf(token, StringComparison.Ordinal) >= 0;
        }

        public static void WriteStatus(string path, string line)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.WriteAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }

        public static void AppendStatus(string path, string line)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }

        public static string ReadAllSafe(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                {
                    return "";
                }
                return File.ReadAllText(path, Encoding.UTF8);
            }
            catch
            {
                return "";
            }
        }

        public static void TryDelete(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }

        public static bool IsSafeProfileName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 64)
            {
                return false;
            }
            if (!name.StartsWith(Constants.ProfilePrefix, StringComparison.Ordinal))
            {
                return false;
            }
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.'))
                {
                    return false;
                }
            }
            if (name.IndexOf("..", StringComparison.Ordinal) >= 0)
            {
                return false;
            }
            return true;
        }

        public static bool PathIsUnder(string child, string parent)
        {
            if (string.IsNullOrEmpty(child) || string.IsNullOrEmpty(parent))
            {
                return false;
            }
            string c = Path.GetFullPath(child).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string p = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.Equals(c, p, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return c.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        public static string QuoteArgument(string arg)
        {
            if (arg == null)
            {
                arg = "";
            }
            bool need = arg.Length == 0;
            for (int i = 0; i < arg.Length && !need; i++)
            {
                char c = arg[i];
                if (c == ' ' || c == '\t' || c == '"' || c == '\n' || c == '\v')
                {
                    need = true;
                }
            }
            if (!need)
            {
                return arg;
            }
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int backslashes = 0;
            for (int i = 0; i < arg.Length; i++)
            {
                char c = arg[i];
                if (c == '\\')
                {
                    backslashes++;
                }
                else if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                    backslashes = 0;
                }
                else
                {
                    if (backslashes > 0)
                    {
                        sb.Append('\\', backslashes);
                        backslashes = 0;
                    }
                    sb.Append(c);
                }
            }
            if (backslashes > 0)
            {
                sb.Append('\\', backslashes * 2);
            }
            sb.Append('"');
            return sb.ToString();
        }

        public static string BuildArguments(string[] arguments)
        {
            StringBuilder sb = new StringBuilder();
            if (arguments == null)
            {
                return "";
            }
            for (int i = 0; i < arguments.Length; i++)
            {
                if (i > 0)
                {
                    sb.Append(' ');
                }
                sb.Append(QuoteArgument(arguments[i]));
            }
            return sb.ToString();
        }

        public static string BuildCommandLine(string exe, string[] arguments)
        {
            string rest = BuildArguments(arguments);
            if (string.IsNullOrEmpty(rest))
            {
                return QuoteArgument(exe);
            }
            return QuoteArgument(exe) + " " + rest;
        }

        public static bool LooksLikeCredentialKey(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                return true;
            }
            string u = key.ToUpperInvariant();
            string[] needles = new string[]
            {
                "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "API_KEY", "APIKEY",
                "BEARER", "PRIVATE_KEY", "ACCESS_KEY", "AWS_", "AZURE_", "OPENAI",
                "ANTHROPIC", "GROK_API", "1PASSWORD"
            };
            for (int i = 0; i < needles.Length; i++)
            {
                if (u.IndexOf(needles[i], StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }
            return false;
        }
    }

    internal sealed class OutputSanitizer
    {
        const int MaxPending = 8192;
        string pending = "";

        public static string Filter(string input)
        {
            OutputSanitizer s = new OutputSanitizer();
            return s.Push(input ?? "") + s.FlushDropIncomplete();
        }

        public string Push(string chunk)
        {
            if (chunk == null)
            {
                chunk = "";
            }
            string s = pending + chunk;
            pending = "";
            StringBuilder sb = new StringBuilder(s.Length);
            int i = 0;
            while (i < s.Length)
            {
                int start = i;
                char c = s[i];
                if (c == '\u001b')
                {
                    int n = ConsumeEsc(s, i);
                    if (n < 0)
                    {
                        pending = s.Substring(i);
                        if (pending.Length > MaxPending)
                        {
                            pending = "";
                        }
                        break;
                    }
                    i = n;
                    continue;
                }
                if (c == '\u009b')
                {
                    int n = ConsumeCsi(s, i + 1);
                    if (n < 0) { pending = s.Substring(i); break; }
                    i = n;
                    continue;
                }
                if (c == '\u009d' || c == '\u0090' || c == '\u0098' || c == '\u009e' || c == '\u009f')
                {
                    int n = ConsumeTerminated(s, i + 1);
                    if (n < 0) { pending = s.Substring(i); break; }
                    i = n;
                    continue;
                }
                if (c == '\t' || c == '\n' || c == '\r')
                {
                    sb.Append(c);
                    i++;
                    continue;
                }
                if (c < 32)
                {
                    i++;
                    continue;
                }
                sb.Append(c);
                i++;
                if (i == start)
                {
                    i++;
                }
            }
            return sb.ToString();
        }

        public string FlushDropIncomplete()
        {
            pending = "";
            return "";
        }

        static int ConsumeEsc(string s, int i)
        {
            if (i + 1 >= s.Length)
            {
                return -1;
            }
            char n = s[i + 1];
            if (n == ']')
            {
                return ConsumeTerminated(s, i + 2);
            }
            if (n == 'P' || n == 'X' || n == '^' || n == '_')
            {
                return ConsumeTerminated(s, i + 2);
            }
            if (n == '[')
            {
                return ConsumeCsi(s, i + 2);
            }
            return i + 2;
        }

        static int ConsumeCsi(string s, int i)
        {
            while (i < s.Length)
            {
                char c = s[i];
                i++;
                if (c >= 0x40 && c <= 0x7E)
                {
                    return i;
                }
            }
            return -1;
        }

        static int ConsumeTerminated(string s, int i)
        {
            while (i < s.Length)
            {
                char c = s[i];
                if (c == '\u0007')
                {
                    return i + 1;
                }
                if (c == '\u009c')
                {
                    return i + 1;
                }
                if (c == '\u001b')
                {
                    if (i + 1 >= s.Length)
                    {
                        return -1;
                    }
                    if (s[i + 1] == '\\')
                    {
                        return i + 2;
                    }
                }
                i++;
            }
            return -1;
        }

        public static JVal SelfCheck()
        {
            JVal o = JVal.Obj();
            Check(o, "plain", Filter("hello"), "hello");
            Check(o, "osc52", Filter("pre\u001b]52;c;QUJDRA==\u0007post"), "prepost");
            Check(o, "json", Filter("{\"a\":1}"), "{\"a\":1}");
            Check(o, "csi_color", Filter("\u001b[31mred\u001b[0m"), "red");
            Check(o, "dcs", Filter("x\u001bP1$tx\u001b\\y"), "xy");
            Check(o, "crlf", Filter("ok\r\n"), "ok\r\n");
            Check(o, "bel_drop", Filter("a\u0007b"), "ab");
            OutputSanitizer st = new OutputSanitizer();
            string a = st.Push("pre\u001b");
            string b = st.Push("]52;c;QUJDRA==\u0007post");
            Check(o, "osc52_cross_chunk", a + b, "prepost");
            bool all = true;
            foreach (KeyValuePair<string, JVal> kv in o.Map)
            {
                if (kv.Key == "all_pass")
                {
                    continue;
                }
                if (kv.Value.Map["pass"].Flag == false)
                {
                    all = false;
                }
            }
            o.Map["all_pass"] = JVal.Bool(all);
            return o;
        }

        static void Check(JVal o, string name, string got, string expect)
        {
            JVal r = JVal.Obj();
            r.Map["pass"] = JVal.Bool(got == expect);
            r.Map["got"] = JVal.Str(got);
            r.Map["expect"] = JVal.Str(expect);
            o.Map[name] = r;
        }
    }

    internal sealed class Clock
    {
        public int Start = Environment.TickCount;
        public int Elapsed
        {
            get { return Environment.TickCount - Start; }
        }
    }

    internal sealed class Log
    {
        readonly string path;
        readonly object gate = new object();

        public Log(string path)
        {
            this.path = path;
        }

        public void Info(string msg)
        {
            string line = DateTime.UtcNow.ToString("o") + " " + msg;
            lock (gate)
            {
                Console.WriteLine(line);
                try
                {
                    if (!string.IsNullOrEmpty(path))
                    {
                        File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
                    }
                }
                catch
                {
                }
            }
        }
    }

    internal sealed class JVal
    {
        public string Kind;
        public string Text;
        public double Number;
        public bool Flag;
        public Dictionary<string, JVal> Map;
        public List<JVal> Items;

        public static JVal Null()
        {
            JVal v = new JVal();
            v.Kind = "null";
            return v;
        }

        public static JVal Str(string s)
        {
            JVal v = new JVal();
            v.Kind = "str";
            v.Text = s ?? "";
            return v;
        }

        public static JVal Num(double n)
        {
            JVal v = new JVal();
            v.Kind = "num";
            v.Number = n;
            return v;
        }

        public static JVal Bool(bool b)
        {
            JVal v = new JVal();
            v.Kind = "bool";
            v.Flag = b;
            return v;
        }

        public static JVal Obj()
        {
            JVal v = new JVal();
            v.Kind = "obj";
            v.Map = new Dictionary<string, JVal>(StringComparer.Ordinal);
            return v;
        }

        public static JVal Arr()
        {
            JVal v = new JVal();
            v.Kind = "arr";
            v.Items = new List<JVal>();
            return v;
        }

        public string AsString(string fallback)
        {
            if (this == null || Kind != "str")
            {
                return fallback;
            }
            return Text;
        }

        public int AsInt(int fallback)
        {
            if (this == null)
            {
                return fallback;
            }
            if (Kind == "num")
            {
                return (int)Number;
            }
            if (Kind == "str")
            {
                int v;
                if (int.TryParse(Text, out v))
                {
                    return v;
                }
            }
            return fallback;
        }

        public bool AsBool(bool fallback)
        {
            if (this == null || Kind != "bool")
            {
                return fallback;
            }
            return Flag;
        }

        public JVal Get(string key)
        {
            if (this == null || Kind != "obj" || Map == null)
            {
                return null;
            }
            JVal v;
            if (Map.TryGetValue(key, out v))
            {
                return v;
            }
            return null;
        }

        public bool GetBool(string key, bool fallback)
        {
            JVal v = Get(key);
            if (v == null)
            {
                return fallback;
            }
            return v.AsBool(fallback);
        }

        public string GetStr(string key, string fallback)
        {
            JVal v = Get(key);
            if (v == null)
            {
                return fallback;
            }
            return v.AsString(fallback);
        }

        public int GetInt(string key, int fallback)
        {
            JVal v = Get(key);
            if (v == null)
            {
                return fallback;
            }
            return v.AsInt(fallback);
        }
    }

    internal static class Json
    {
        public static JVal Parse(string s)
        {
            if (s == null)
            {
                s = "";
            }
            if (s.Length > Constants.JsonMaxBytes)
            {
                throw new InvalidOperationException("json too large");
            }
            Parser p = new Parser(s);
            JVal v = p.ParseValue(0);
            p.SkipWs();
            if (p.Pos != p.Text.Length)
            {
                throw new InvalidOperationException("json trailing junk at " + p.Pos);
            }
            return v;
        }

        public static string Stringify(JVal v)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, v, 0);
            sb.Append('\n');
            return sb.ToString();
        }

        static void Write(StringBuilder sb, JVal v, int indent)
        {
            if (v == null || v.Kind == "null")
            {
                sb.Append("null");
                return;
            }
            if (v.Kind == "bool")
            {
                sb.Append(v.Flag ? "true" : "false");
                return;
            }
            if (v.Kind == "num")
            {
                if (v.Number == Math.Truncate(v.Number) && Math.Abs(v.Number) < 9007199254740991)
                {
                    sb.Append(((long)v.Number).ToString(CultureInfo.InvariantCulture));
                }
                else
                {
                    sb.Append(v.Number.ToString("R", CultureInfo.InvariantCulture));
                }
                return;
            }
            if (v.Kind == "str")
            {
                sb.Append(Esc(v.Text));
                return;
            }
            if (v.Kind == "arr")
            {
                sb.Append('[');
                for (int i = 0; i < v.Items.Count; i++)
                {
                    if (i > 0)
                    {
                        sb.Append(", ");
                    }
                    Write(sb, v.Items[i], indent);
                }
                sb.Append(']');
                return;
            }
            sb.Append("{\n");
            int n = 0;
            foreach (KeyValuePair<string, JVal> kv in v.Map)
            {
                if (n > 0)
                {
                    sb.Append(",\n");
                }
                Pad(sb, indent + 1);
                sb.Append(Esc(kv.Key)).Append(": ");
                Write(sb, kv.Value, indent + 1);
                n++;
            }
            if (n > 0)
            {
                sb.Append('\n');
            }
            Pad(sb, indent);
            sb.Append('}');
        }

        static void Pad(StringBuilder sb, int indent)
        {
            for (int i = 0; i < indent; i++)
            {
                sb.Append("  ");
            }
        }

        public static string Esc(string s)
        {
            if (s == null)
            {
                return "null";
            }
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 32) sb.AppendFormat("\\u{0:x4}", (int)c);
                else sb.Append(c);
            }
            sb.Append('"');
            return sb.ToString();
        }

        sealed class Parser
        {
            public readonly string Text;
            public int Pos;
            int nodes;

            public Parser(string t)
            {
                Text = t;
            }

            void CountNode()
            {
                nodes++;
                if (nodes > Constants.JsonMaxNodes)
                {
                    throw new InvalidOperationException("json too many nodes");
                }
            }

            public void SkipWs()
            {
                while (Pos < Text.Length)
                {
                    char c = Text[Pos];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                    {
                        Pos++;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            public JVal ParseValue(int depth)
            {
                if (depth > Constants.JsonMaxDepth)
                {
                    throw new InvalidOperationException("json too deep");
                }
                CountNode();
                SkipWs();
                if (Pos >= Text.Length)
                {
                    throw new InvalidOperationException("json eof");
                }
                char c = Text[Pos];
                if (c == '{')
                {
                    return ParseObj(depth);
                }
                if (c == '[')
                {
                    return ParseArr(depth);
                }
                if (c == '"')
                {
                    return JVal.Str(ParseString());
                }
                if (c == 't' || c == 'f')
                {
                    return JVal.Bool(ParseBool());
                }
                if (c == 'n')
                {
                    ParseLit("null");
                    return JVal.Null();
                }
                return JVal.Num(ParseNum());
            }

            JVal ParseObj(int depth)
            {
                Pos++;
                JVal o = JVal.Obj();
                SkipWs();
                if (Pos < Text.Length && Text[Pos] == '}')
                {
                    Pos++;
                    return o;
                }
                while (true)
                {
                    SkipWs();
                    string key = ParseString();
                    if (o.Map.ContainsKey(key))
                    {
                        throw new InvalidOperationException("json duplicate key");
                    }
                    SkipWs();
                    if (Pos >= Text.Length || Text[Pos] != ':')
                    {
                        throw new InvalidOperationException("json expected colon");
                    }
                    Pos++;
                    o.Map[key] = ParseValue(depth + 1);
                    SkipWs();
                    if (Pos < Text.Length && Text[Pos] == ',')
                    {
                        Pos++;
                        continue;
                    }
                    if (Pos < Text.Length && Text[Pos] == '}')
                    {
                        Pos++;
                        return o;
                    }
                    throw new InvalidOperationException("json expected object end");
                }
            }

            JVal ParseArr(int depth)
            {
                Pos++;
                JVal a = JVal.Arr();
                SkipWs();
                if (Pos < Text.Length && Text[Pos] == ']')
                {
                    Pos++;
                    return a;
                }
                while (true)
                {
                    a.Items.Add(ParseValue(depth + 1));
                    SkipWs();
                    if (Pos < Text.Length && Text[Pos] == ',')
                    {
                        Pos++;
                        continue;
                    }
                    if (Pos < Text.Length && Text[Pos] == ']')
                    {
                        Pos++;
                        return a;
                    }
                    throw new InvalidOperationException("json expected array end");
                }
            }

            string ParseString()
            {
                SkipWs();
                if (Pos >= Text.Length || Text[Pos] != '"')
                {
                    throw new InvalidOperationException("json expected string");
                }
                Pos++;
                StringBuilder sb = new StringBuilder();
                while (Pos < Text.Length)
                {
                    char c = Text[Pos++];
                    if (c == '"')
                    {
                        return sb.ToString();
                    }
                    if (c == '\\')
                    {
                        if (Pos >= Text.Length)
                        {
                            throw new InvalidOperationException("json bad escape");
                        }
                        char e = Text[Pos++];
                        if (e == '"' || e == '\\' || e == '/') sb.Append(e);
                        else if (e == 'n') sb.Append('\n');
                        else if (e == 'r') sb.Append('\r');
                        else if (e == 't') sb.Append('\t');
                        else if (e == 'b') sb.Append('\b');
                        else if (e == 'f') sb.Append('\f');
                        else if (e == 'u' && Pos + 4 <= Text.Length)
                        {
                            int cp = int.Parse(Text.Substring(Pos, 4), NumberStyles.HexNumber);
                            sb.Append((char)cp);
                            Pos += 4;
                        }
                        else throw new InvalidOperationException("json bad escape");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }
                throw new InvalidOperationException("json unterminated string");
            }

            bool ParseBool()
            {
                if (Text.Substring(Pos).StartsWith("true"))
                {
                    Pos += 4;
                    return true;
                }
                if (Text.Substring(Pos).StartsWith("false"))
                {
                    Pos += 5;
                    return false;
                }
                throw new InvalidOperationException("json bad bool");
            }

            void ParseLit(string lit)
            {
                if (!Text.Substring(Pos).StartsWith(lit))
                {
                    throw new InvalidOperationException("json expected " + lit);
                }
                Pos += lit.Length;
            }

            double ParseNum()
            {
                int start = Pos;
                if (Pos < Text.Length && Text[Pos] == '-')
                {
                    Pos++;
                }
                while (Pos < Text.Length && Text[Pos] >= '0' && Text[Pos] <= '9')
                {
                    Pos++;
                }
                if (Pos < Text.Length && Text[Pos] == '.')
                {
                    Pos++;
                    while (Pos < Text.Length && Text[Pos] >= '0' && Text[Pos] <= '9')
                    {
                        Pos++;
                    }
                }
                return double.Parse(Text.Substring(start, Pos - start), CultureInfo.InvariantCulture);
            }
        }
    }

    internal static class Constants
    {
        public const string ProfilePrefix = "nmzp.agent.";
        public const string ComponentName = "native-agent-sandbox";
        public const int PhaseTimeoutMs = 15000;
        public const int FixtureDeadlineMs = 20000;
        public const int OverallTimeoutMs = 180000;
        public const int ProbeConnectTimeoutMs = 1500;
        public const int DescendantWaitMs = 8000;
        public const int ProductionDefaultDeadlineMs = 1800000;
        public const int ProductionMaxDeadlineMs = 3600000;
        public const int JsonMaxBytes = 262144;
        public const int JsonMaxDepth = 16;
        public const int JsonMaxNodes = 4096;
        public const int StdoutMaxBytes = 1048576;
        public const uint RequiredUiFlags =
            Native.JOB_OBJECT_UILIMIT_HANDLES |
            Native.JOB_OBJECT_UILIMIT_READCLIPBOARD |
            Native.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
            Native.JOB_OBJECT_UILIMIT_DESKTOP |
            Native.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
        public static readonly uint FixtureColor = Native.Rgb(0xC0, 0x11, 0xE5);
        public const string FixtureClass = "NMZP.NAS.Fixture";
        public const string FixtureTitle = "NMZP-NAS-FIXTURE";
    }
}
