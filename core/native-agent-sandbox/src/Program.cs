using System;
using System.IO;
using System.Text;

namespace NativeAgentSandbox
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            try
            {
                if (Args.HasFlag(args, "--controller-identity")) return ControllerIdentity.Run(Args.Get(args,"--controller-identity"));
                if (Args.HasFlag(args, "--privileged-init") || Args.HasFlag(args, "--dry-plan"))
                {
                    return PrivilegedInit.Run(args);
                }
                if (Args.HasFlag(args, "--probe"))
                {
                    string mode = Args.Get(args, "--probe");
                    if (IsPublicUiProbe(mode))
                    {
                        string ticket = Args.Get(args, "--dispatch-ticket");
                        string derr;
                        if (string.IsNullOrEmpty(ticket) || !InternalDispatch.TryValidate(ticket, mode, out derr))
                        {
                            Console.Error.WriteLine("refused: UI/fixture probes are not a public command");
                            return 2;
                        }
                    }
                    return Probe.Run(args);
                }
                if (Args.HasFlag(args, "--pure-self-test")) return PureSelfTest.Run();
                if (Args.HasFlag(args, "--self-test"))
                {
                    return SelfTest.Run(args);
                }
                if (Args.HasFlag(args, "--delete-profile"))
                {
                    Console.Error.WriteLine("refused: --delete-profile is not a production command");
                    return 2;
                }
                if (Args.HasFlag(args, "--config"))
                {
                    return Supervisor.RunConfigFile(Args.Get(args, "--config"), Args.Get(args, "--result"));
                }
                PrintUsage();
                return 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("FATAL " + ex.GetType().Name + ": " + TextUtil.Sanitize(ex.Message));
                return 1;
            }
        }

        static bool IsPublicUiProbe(string mode)
        {
            if (string.IsNullOrEmpty(mode))
            {
                return false;
            }
            return string.Equals(mode, "ui", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "ui-child", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "fixture-owner", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "winsta-holder", StringComparison.OrdinalIgnoreCase);
        }

        static void PrintUsage()
        {
            Console.WriteLine("NativeAgentSandbox");
            Console.WriteLine("  --config <file.json> [--result <out.json>]");
            Console.WriteLine("  --self-test --out <dir>");
            Console.WriteLine("  --privileged-init --dry-plan");
            Console.WriteLine("Production: LPAC + required Job UI limits + named job Local\\<profile>.job.");
            Console.WriteLine("network_mode=offline|brokered (brokered refuses until WFP helper is installed).");
            Console.WriteLine("Elevated --config is refused. Do not run --execute-payload or UI capture before root final review.");
            Console.WriteLine("Failures do not degrade to a normal process. Profile cleanup is only for profiles this process created.");
        }
    }
}
