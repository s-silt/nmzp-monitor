using System;
namespace NativeAgentSandbox
{
    internal static class PureSelfTest
    {
        static int count;
        static void Check(bool ok, string name) { count++; if (!ok) throw new Exception("pure test failed: " + name); }
        public static int Run()
        {
            int resumes = 0; uint previous; string error;
            Func<uint> resume = delegate { resumes++; return 1; };
            Check(!ResumeBarrier.TryResume(delegate { return false; }, delegate { return true; }, resume, out previous, out error), "bind/prepare proof failed");
            Check(resumes == 0, "failure never resumes even if termination cannot be proven");
            Check(!ResumeBarrier.TryResume(delegate { return true; }, delegate { return false; }, resume, out previous, out error), "controller lost");
            Check(resumes == 0, "controller lost never resumes");
            Check(!ResumeBarrier.TryResume(delegate { throw new Exception(); }, delegate { return true; }, resume, out previous, out error), "query throws");
            Check(resumes == 0, "unknown proof never resumes");
            Check(ResumeBarrier.TryResume(delegate { return true; }, delegate { return true; }, resume, out previous, out error), "normal proof resumes");
            Check(resumes == 1 && previous == 1, "exactly once");
            Check(!ResumeBarrier.TryResume(delegate { return true; }, delegate { return true; }, delegate { return uint.MaxValue; }, out previous, out error), "native failure");
            Check(!ResumeBarrier.TryResume(delegate { return true; }, delegate { return true; }, delegate { return 0; }, out previous, out error), "unexpected running thread");
            string prefix = "{\"network_mode\":\"brokered\",\"gateway_port\":12345,\"controller_pid\":123,\"controller_creation_time\":";
            LaunchRequest r = Config.FromJson(prefix + "\"134030000000000001\"}");
            Check(r.ControllerCreationTime == 134030000000000001L, "exact FILETIME above 2^53");
            foreach (string bad in new string[] { "134030000000000001", "\"1e17\"", "\"+123\"", "\"-1\"", "\" 123\"", "\"9223372036854775808\"" }) {
                bool refused = false; try { Config.FromJson(prefix + bad + "}"); } catch { refused = true; }
                Check(refused, "invalid FILETIME");
            }
            foreach (string field in new string[] { "FilterWorld", "InjectSkipJobAssign", "AfterBindHook", "SkipPrivateDesktopForBrokeredTest", "ExistingAc", "trusted", "environment_allowlist" }) {
                bool refused = false; try { Config.FromJson("{\"" + field + "\":true}"); } catch { refused = true; }
                Check(refused, "external test flag refused");
            }
            foreach(string p in new string[]{"src/main.ts","test-1.txt","README.md"}) Check(GrokSessionSpec.SafeRelative(p),"workspace relative path");
            foreach(string p in new string[]{"../secret","C:/secret","a:stream",".env",".env.local","a/.git/config","a/.grok/config.toml","a/CON.txt","a/..","a/","a\\b","a\n"}) Check(!GrokSessionSpec.SafeRelative(p),"workspace boundary");
            string spec="{\"model\":\"nmzp-proof\",\"session_token\":\""+new string('a',64)+"\",\"executable_sha256\":\""+new string('b',64)+"\",\"pipe\":\"nmzp-owned-"+new string('c',64)+"\",\"control_token\":\""+new string('d',64)+"\",\"files\":[],\"tools\":[]}";
            GrokSessionSpec gs=GrokSessionSpec.Parse(Json.Parse(spec));
            Check(gs.Toml(12345).Contains("http://127.0.0.1:12345/v1"),"private gateway config");
            Check(gs.Toml(12345).Contains("remember_tool_approvals = false"),"approval intent remains explicit");
            bool inject=false; try { GrokSessionSpec.Parse(Json.Parse(spec.Replace("nmzp-proof","bad\\nfield"))); } catch { inject=true; }
            Check(inject,"TOML injection refused");
            Console.WriteLine("{\"pass\":" + count + ",\"fail\":0,\"scope\":\"pure-no-os-mutations\",\"production_ready\":false}");
            return 0;
        }
    }
}
