namespace Trawler.Common
{
	public class TrawlerContext
	{
		private DetectionTracker DetectionTracker { get; }

		private SnapshotTracker SnapshotTracker { get; }

		private string TargetDrive { get; }

		private bool Quiet { get; }

		public TrawlerContext(string detectionPath, string loadSnapshotPath)
		{
			DetectionTracker = new DetectionTracker(detectionPath);
			SnapshotTracker = new SnapshotTracker(loadSnapshotPath);
		}

		public TrawlerContext(CommandLineOptions options)
		{
			DetectionTracker = new DetectionTracker(options.DetectionPath);

			if (!string.IsNullOrWhiteSpace(options.LoadSnapshotPath))
			{
				SnapshotTracker = new SnapshotTracker(options.LoadSnapshotPath);
			}

			Quiet = options.Quiet;

			if (!string.IsNullOrWhiteSpace(options.TargetDrive))
			{
				Environment.SetEnvironmentVariable("TrawlerTargetDrive", options.TargetDrive, EnvironmentVariableTarget.Process);
				// refactor to a DriveRetargeting class
				TargetDrive = options.TargetDrive;
			}
		}

		~TrawlerContext()
		{
			Environment.SetEnvironmentVariable("TrawlerTargetDrive", null, EnvironmentVariableTarget.Process);
		}
	}
}

