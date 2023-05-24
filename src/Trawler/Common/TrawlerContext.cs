using System;
namespace Trawler.Common
{
	public class TrawlerContext
	{
		private DetectionTracker DetectionTracker { get; }

		private SnapshotTracker SnapshotTracker { get; }

		public TrawlerContext(string detectionPath, string loadSnapshotPath)
		{
			DetectionTracker = new DetectionTracker(detectionPath);
			SnapshotTracker = new SnapshotTracker(loadSnapshotPath);
		}
	}
}

