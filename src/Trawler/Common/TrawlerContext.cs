namespace Trawler.Common
{
	public class TrawlerContext
	{
		private DetectionTracker DetectionTracker { get; }

		private SnapshotTracker SnapshotTracker { get; }

		private string TargetDrive { get; }

		private bool Quiet { get; }

		private bool _canWriteSnapshot { get; }

		public TrawlerContext(string detectionPath, string loadSnapshotPath)
		{
			DetectionTracker = new DetectionTracker(detectionPath);
			SnapshotTracker = new SnapshotTracker(loadSnapshotPath);
		}

		public TrawlerContext(CommandLineOptions options)
		{
			DetectionTracker = new DetectionTracker(options.DetectionPath);

            _canWriteSnapshot = string.IsNullOrWhiteSpace(options.LoadSnapshotPath);

			if (!_canWriteSnapshot)
			{
				SnapshotTracker = new SnapshotTracker(options.LoadSnapshotPath);
			}

			Quiet = options.Quiet;

			if (!string.IsNullOrWhiteSpace(options.TargetDrive))
			{
				Environment.SetEnvironmentVariable("TrawlerTargetDrive", options.TargetDrive, EnvironmentVariableTarget.Process);
			}
		}

		public void WriteDetection(Detection detection)
		{
			DetectionTracker.Detections.Add(detection);
		}

		public void WriteSnapshot(Snapshot snapshot)
		{
			if (!_canWriteSnapshot)
			{
				return;
			}

			if (string.IsNullOrWhiteSpace(snapshot.Value))
			{
				SnapshotTracker.Write(snapshot.Source, snapshot.Key);
			}
			else
			{
				SnapshotTracker.Write(snapshot.Source, snapshot.Key, snapshot.Value);
			}
		}

        public bool CheckSnapshotBaseline(Snapshot snapshot)
        {
            if (!_canWriteSnapshot)
            {
                return false;
            }

			return string.IsNullOrWhiteSpace(snapshot.Value) ? 
                SnapshotTracker.CheckKey(snapshot.Source, snapshot.Key) :
                SnapshotTracker.CheckKvp(snapshot.Source, snapshot.Key, snapshot.Value);
        }

		~TrawlerContext()
		{
			Environment.SetEnvironmentVariable("TrawlerTargetDrive", null, EnvironmentVariableTarget.Process);
		}
	}
}

