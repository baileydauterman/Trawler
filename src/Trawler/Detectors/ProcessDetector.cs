using System.Diagnostics;
using Trawler.Common;
using Trawler.Constants;

namespace Trawler.Detectors
{
    internal class ProcessDetector : Detector
    {
        public ProcessDetector(TrawlerContext context)
            : base(context, source)
        {
        }

        public void Run()
        {
            var processes = Process.GetProcesses();

            foreach (var process in processes)
            {
                if (!ShouldProcess(process))
                {
                    continue;
                }
            }
        }

        private bool ShouldProcess(Process process)
        {
            var snapshot = new Snapshot
            {
                Source = source,
                Key = process.ProcessName,
                Value = process.MainModule?.FileName ?? string.Empty
            };

            Context.WriteSnapshot(snapshot);
            return Context.CheckSnapshotBaseline(snapshot);
        }

        private void Process(Process process)
        {
            var ipv4Match = Regexes.IPv4Pattern.Match(process.StartInfo.Arguments);
            var ipv6Match = Regexes.IPv6Pattern.Match(process.StartInfo.Arguments);

            if (ipv4Match.Success || ipv6Match.Success)
            {
                var detection = new Detection
                {
                    Name = "IP Address Pattern detected in Process CommandLine",
                    Risk = Risk.Medium,
                    Source = source,
                    Technique = "T1059: Command and Scripting Interpreter",
                    Meta = $"Process Name: {process.ProcessName}, CommandLine: {process.StartInfo.Arguments}, Executable: {process.StartInfo.WorkingDirectory}"
                };

                Context.WriteDetection(detection);
            }
        }

        private const string source = "Processes";
    }
}
