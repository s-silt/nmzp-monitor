using System;
using System.IO;
using System.Text;

namespace Nmzp.NativeEgressFilter
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = new UTF8Encoding(false);
                if (args == null || args.Length == 0)
                {
                    Usage("missing_command");
                    return 2;
                }
                string cmd = args[0];
                if (HasDisallowed(args))
                {
                    Console.WriteLine(ResultJson.Emit(false, cmd, false, false, false, "disallowed_arg", null, null, null));
                    return 2;
                }
                if (string.Equals(cmd, "selftest", StringComparison.Ordinal))
                {
                    if (args.Length != 1)
                    {
                        Console.WriteLine(ResultJson.Emit(false, cmd, false, false, false, "selftest_no_args", null, null, null));
                        return 2;
                    }
                    return SelfTest.Run();
                }
                if (string.Equals(cmd, "prepare", StringComparison.Ordinal)
                    || string.Equals(cmd, "plan", StringComparison.Ordinal)
                    || string.Equals(cmd, "status", StringComparison.Ordinal)
                    || string.Equals(cmd, "apply", StringComparison.Ordinal)
                    || string.Equals(cmd, "cleanup", StringComparison.Ordinal))
                {
                    string spec;
                    string err;
                    if (!TryReadSpec(args, out spec, out err))
                    {
                        Console.WriteLine(ResultJson.Emit(false, cmd, false, false, false, err, null, null, null));
                        return 2;
                    }
                    if (cmd == "prepare" || cmd == "plan") return Commands.PrepareOrPlan(cmd, spec);
                    if (cmd == "status") return Commands.Status(spec);
                    if (cmd == "apply") return Commands.Apply(spec);
                    return Commands.Cleanup(spec);
                }
                Usage("unknown_command");
                return 2;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ResultJson.Emit(false, "fatal", false, false, false, "exception:" + ex.GetType().Name, null, null, null));
                return 1;
            }
        }

        static bool HasDisallowed(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == null) continue;
                if (!(a.StartsWith("-", StringComparison.Ordinal) || a.StartsWith("/", StringComparison.Ordinal)))
                {
                    continue;
                }
                string l = a.ToLowerInvariant();
                if (l == "--runas" || l == "/runas" || l == "--dll" || l.StartsWith("--dll=", StringComparison.Ordinal) || l == "--load")
                {
                    return true;
                }
            }
            return false;
        }

        static bool TryReadSpec(string[] args, out string spec, out string error)
        {
            spec = null;
            error = null;
            string path = null;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--spec-file" && i + 1 < args.Length)
                {
                    if (path != null)
                    {
                        error = "duplicate_spec_file";
                        return false;
                    }
                    path = args[i + 1];
                    i++;
                    continue;
                }
                error = "unknown_arg";
                return false;
            }
            if (string.IsNullOrEmpty(path))
            {
                error = "missing_spec_file";
                return false;
            }
            if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                error = "spec_path";
                return false;
            }
            try
            {
                if (!File.Exists(path))
                {
                    error = "spec_file_missing";
                    return false;
                }
                FileInfo fi = new FileInfo(path);
                if (fi.Length > Json.MaxSpecBytes)
                {
                    error = "spec_size";
                    return false;
                }
                spec = File.ReadAllText(path, Encoding.UTF8);
                if (spec.Length > Json.MaxSpecBytes)
                {
                    error = "spec_size";
                    spec = null;
                    return false;
                }
                return true;
            }
            catch
            {
                error = "spec_file_read";
                return false;
            }
        }

        static void Usage(string error)
        {
            Console.WriteLine(ResultJson.Emit(false, "usage", false, false, false, error, null, null, null));
        }
    }
}
