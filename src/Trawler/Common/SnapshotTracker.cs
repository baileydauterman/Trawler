namespace Trawler.Common
{
	public class SnapshotTracker
	{
		public List<Snapshot> Data { get; }

		public bool HasData => Data.Any();

		public SnapshotTracker(string path)
		{
			if (!File.Exists(path))
			{
				throw new FileNotFoundException(path);
			}

			Data = LoadCsv(path);
		}

		private List<Snapshot> LoadCsv(string path)
		{
			return Enumerable.Empty<Snapshot>().ToList();
		}

		public bool CheckKey(string source, string key)
		{
			return Data.Select(k => k.Source.Equals(source) && k.Key.Equals(key)).Any();
		}

		public bool CheckKvp(string source, string key, string value)
		{
			return Data.Select(k => k.Source.Equals(source) && k.Key.Equals(key) && k.Value.Equals(value)).Any();
		}

		public void Write(string source, string key)
		{
            try
            {

            }
            catch
            {
                // catch file writing errors
            }
        }

		public void Write(string source, string key, string value)
		{
			try
			{

			}
			catch
			{
				// catch file writing errors
			}
		}
	}
}

