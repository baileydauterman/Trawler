using System;
using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using System.Xml.Linq;

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
                File.OpenWrite(path).Close();
            }
            catch
            {
                throw new FileNotFoundException($"Unable to open and write to {path}");
            }
        }

        public string GetConsoleColor(Risk risk)
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
