// Strict JSON: unknown fields rejected by callers, duplicate keys rejected,
// comments/trailing commas rejected, size limited.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Nmzp.NativeEgressFilter
{
    internal sealed class JsonObject
    {
        public readonly List<string> Keys = new List<string>();
        public readonly Dictionary<string, object> Map = new Dictionary<string, object>(StringComparer.Ordinal);
    }

    internal static class Json
    {
        public const int MaxSpecBytes = 8192;
        public const int MaxDepth = 4;
        public const int MaxString = 256;

        public static object Parse(string text)
        {
            if (text == null)
            {
                throw new JsonException("empty");
            }
            Parser p = new Parser(text);
            object v = p.ParseValue(0);
            p.SkipWs();
            if (p.Pos != p.Len)
            {
                throw new JsonException("trailing_data");
            }
            return v;
        }

        public static JsonObject AsObject(object v, string ctx)
        {
            JsonObject o = v as JsonObject;
            if (o == null)
            {
                throw new JsonException(ctx + ":expected_object");
            }
            return o;
        }

        public static string ReqString(JsonObject o, string key)
        {
            object v;
            if (!o.Map.TryGetValue(key, out v))
            {
                throw new JsonException("missing:" + key);
            }
            string s = v as string;
            if (s == null)
            {
                throw new JsonException("not_string:" + key);
            }
            return s;
        }

        public static int ReqInt(JsonObject o, string key)
        {
            object v;
            if (!o.Map.TryGetValue(key, out v))
            {
                throw new JsonException("missing:" + key);
            }
            if (!(v is long))
            {
                throw new JsonException("not_int:" + key);
            }
            long n = (long)v;
            if (n < int.MinValue || n > int.MaxValue)
            {
                throw new JsonException("int_range:" + key);
            }
            return (int)n;
        }

        public static JsonObject ReqObject(JsonObject o, string key)
        {
            object v;
            if (!o.Map.TryGetValue(key, out v))
            {
                throw new JsonException("missing:" + key);
            }
            return AsObject(v, key);
        }

        public static void RejectUnknown(JsonObject o, params string[] allowed)
        {
            for (int i = 0; i < o.Keys.Count; i++)
            {
                string k = o.Keys[i];
                bool ok = false;
                for (int j = 0; j < allowed.Length; j++)
                {
                    if (string.Equals(k, allowed[j], StringComparison.Ordinal))
                    {
                        ok = true;
                        break;
                    }
                }
                if (!ok)
                {
                    throw new JsonException("unknown_field:" + k);
                }
            }
        }

        public static string Escape(string s)
        {
            if (s == null)
            {
                return "null";
            }
            StringBuilder sb = new StringBuilder(s.Length + 8);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 32)
                {
                    sb.Append("\\u");
                    sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                }
                else sb.Append(c);
            }
            sb.Append('"');
            return sb.ToString();
        }

        sealed class Parser
        {
            readonly string s;
            public readonly int Len;
            public int Pos;

            public Parser(string text)
            {
                s = text;
                Len = text.Length;
                Pos = 0;
                if (Len >= 3 && s[0] == (char)0xFEFF)
                {
                    Pos = 1;
                }
            }

            public void SkipWs()
            {
                while (Pos < Len)
                {
                    char c = s[Pos];
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

            public object ParseValue(int depth)
            {
                if (depth > Json.MaxDepth)
                {
                    throw new JsonException("depth");
                }
                SkipWs();
                if (Pos >= Len)
                {
                    throw new JsonException("eof");
                }
                char c = s[Pos];
                if (c == '{') return ParseObject(depth + 1);
                if (c == '[') return ParseArray(depth + 1);
                if (c == '"') return ParseString();
                if (c == 't') { Expect("true"); return true; }
                if (c == 'f') { Expect("false"); return false; }
                if (c == 'n') { Expect("null"); return null; }
                if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();
                throw new JsonException("unexpected");
            }

            List<object> ParseArray(int depth)
            {
                Pos++;
                List<object> a = new List<object>();
                SkipWs();
                if (Pos < Len && s[Pos] == ']')
                {
                    Pos++;
                    return a;
                }
                while (true)
                {
                    a.Add(ParseValue(depth));
                    if (a.Count > 32)
                    {
                        throw new JsonException("array_too_long");
                    }
                    SkipWs();
                    if (Pos >= Len) throw new JsonException("array_eof");
                    if (s[Pos] == ',')
                    {
                        Pos++;
                        SkipWs();
                        if (Pos < Len && s[Pos] == ']')
                        {
                            throw new JsonException("trailing_comma");
                        }
                        continue;
                    }
                    if (s[Pos] == ']')
                    {
                        Pos++;
                        return a;
                    }
                    throw new JsonException("array_sep");
                }
            }

            JsonObject ParseObject(int depth)
            {
                Pos++;
                JsonObject o = new JsonObject();
                SkipWs();
                if (Pos < Len && s[Pos] == '}')
                {
                    Pos++;
                    return o;
                }
                while (true)
                {
                    SkipWs();
                    if (Pos >= Len || s[Pos] != '"')
                    {
                        throw new JsonException("object_key");
                    }
                    string key = ParseString();
                    if (o.Map.ContainsKey(key))
                    {
                        throw new JsonException("duplicate_key:" + key);
                    }
                    SkipWs();
                    if (Pos >= Len || s[Pos] != ':')
                    {
                        throw new JsonException("colon");
                    }
                    Pos++;
                    object val = ParseValue(depth);
                    o.Keys.Add(key);
                    o.Map[key] = val;
                    SkipWs();
                    if (Pos >= Len)
                    {
                        throw new JsonException("object_eof");
                    }
                    if (s[Pos] == ',')
                    {
                        Pos++;
                        SkipWs();
                        if (Pos < Len && s[Pos] == '}')
                        {
                            throw new JsonException("trailing_comma");
                        }
                        continue;
                    }
                    if (s[Pos] == '}')
                    {
                        Pos++;
                        return o;
                    }
                    throw new JsonException("object_sep");
                }
            }

            string ParseString()
            {
                Pos++;
                StringBuilder sb = new StringBuilder();
                while (Pos < Len)
                {
                    char c = s[Pos];
                    if (c == '"')
                    {
                        Pos++;
                        if (sb.Length > Json.MaxString)
                        {
                            throw new JsonException("string_too_long");
                        }
                        return sb.ToString();
                    }
                    if (c == '\\')
                    {
                        Pos++;
                        if (Pos >= Len) throw new JsonException("escape_eof");
                        char e = s[Pos];
                        Pos++;
                        if (e == '"' || e == '\\' || e == '/') sb.Append(e);
                        else if (e == 'b') sb.Append('\b');
                        else if (e == 'f') sb.Append('\f');
                        else if (e == 'n') sb.Append('\n');
                        else if (e == 'r') sb.Append('\r');
                        else if (e == 't') sb.Append('\t');
                        else if (e == 'u')
                        {
                            if (Pos + 4 > Len) throw new JsonException("u_eof");
                            int cp = 0;
                            for (int i = 0; i < 4; i++)
                            {
                                cp = (cp << 4) + Hex(s[Pos + i]);
                            }
                            Pos += 4;
                            sb.Append((char)cp);
                        }
                        else throw new JsonException("bad_escape");
                        continue;
                    }
                    if (c < 32)
                    {
                        throw new JsonException("unescaped_control");
                    }
                    sb.Append(c);
                    Pos++;
                }
                throw new JsonException("string_eof");
            }

            long ParseNumber()
            {
                int start = Pos;
                if (s[Pos] == '-') Pos++;
                if (Pos >= Len || s[Pos] < '0' || s[Pos] > '9')
                {
                    throw new JsonException("number");
                }
                if (s[Pos] == '0')
                {
                    Pos++;
                    if (Pos < Len && s[Pos] >= '0' && s[Pos] <= '9')
                    {
                        throw new JsonException("leading_zero");
                    }
                }
                else
                {
                    while (Pos < Len && s[Pos] >= '0' && s[Pos] <= '9') Pos++;
                }
                if (Pos < Len && (s[Pos] == '.' || s[Pos] == 'e' || s[Pos] == 'E'))
                {
                    throw new JsonException("not_int");
                }
                string t = s.Substring(start, Pos - start);
                long n;
                if (!long.TryParse(t, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out n))
                {
                    throw new JsonException("int_parse");
                }
                return n;
            }

            void Expect(string lit)
            {
                if (Pos + lit.Length > Len || s.Substring(Pos, lit.Length) != lit)
                {
                    throw new JsonException("literal");
                }
                Pos += lit.Length;
            }

            static int Hex(char c)
            {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                throw new JsonException("hex");
            }
        }
    }

    internal sealed class JsonException : Exception
    {
        public JsonException(string m) : base(m) { }
    }
}
