namespace Trawler.Common
{
    /// <summary>
    /// </summary>
    public class DetectionTracker
    {
        public List<Detection> Detections { get; } = new();

        public DetectionTracker(string path)
        {
            try
            {
                // clear file before starting
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                File.OpenWrite(path).Close();
            }
            catch
            {
                throw new FileNotFoundException($"Unable to open and write to {path}");
            }
        }

        public static string GetConsoleColor(Risk risk)
        {
            return risk switch
            {
                Risk.VeryLow => "Green",
                Risk.Low => "Green",
                Risk.Medium => "Yellow",
                Risk.High => "Red",
                Risk.VeryHigh => "Magenta",
                _ => "Yellow",
            };
        }
    }
}
