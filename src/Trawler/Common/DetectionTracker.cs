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

        public void Add(Detection detection)
        {
            Detections.Add(detection);

        }

        public void WriteDetection(Detection detection)
        {
            var previousConsoleColor = Console.ForegroundColor;
            var prefix = GetMessagePrefix(LogLevel.None);

            Console.ForegroundColor = GetConsoleColor(detection.Risk);
            ConsoleWriter.Write($"{prefix}Detection: {detection.Name} - Risk: {detection.Risk}");
            Console.ForegroundColor = previousConsoleColor;
        }

        public static ConsoleColor GetConsoleColor(Risk risk)
        {
            return risk switch
            {
                Risk.VeryLow => ConsoleColor.Green,
                Risk.Low => ConsoleColor.Green,
                Risk.Medium => ConsoleColor.Yellow,
                Risk.High => ConsoleColor.Red,
                Risk.VeryHigh => ConsoleColor.Magenta,
                _ => ConsoleColor.Yellow,
            };
        }

        public static string GetMessagePrefix(LogLevel level)
        {
            return level switch
            {
                LogLevel.None => "[!] ",
                LogLevel.Info => "[%] ",
                _ => string.Empty,
            };
        }
    }
}
