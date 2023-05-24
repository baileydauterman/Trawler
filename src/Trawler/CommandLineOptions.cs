using CommandLine;
using Trawler.Common;

namespace Trawler
{
    public class CommandLineOptions
    {
        [Option('d', "detection_path", Required = false, HelpText = "The fully-qualified file-path where detection output should be stored as a CSV, defaults to location of exe")]
        public string DetectionPath { get; set; } = Path.Combine(Directory.GetCurrentDirectory(), "detections.csv");

        [Option('s', "snapshot", Required = false, HelpText = "Should a snapshot CSV be generated")]
        public bool Snapshot { get; set; } = false;

        [Option('l', "load_snapshot", Required = false, HelpText = "Path to a snapshot")]
        public string? LoadSnapshotPath { get; set; }

        [Option('q', "quiet", Required = false, HelpText = "Suppress Detection Output to Console")]
        public bool Quiet { get; set; } = false;

        [Option('t', "target_drive", Required = false, HelpText = "The drive to target for analysis - for example, if mounting an imaged system as a second drive on an analysis device, specify via -drivetarget \"D:\" (NOT YET IMPLEMENTED)")]
        public string? TargetDrive { get; set; }

        [Option('o', "scan_options", Required = false, HelpText = "Allows for targeting certain scanners and ignoring others. Use 'All' to run all scanners. (Split by comma)")]
        public ScanOptions ScanOptions { get; set; } = ScanOptions.All;
    }
}
