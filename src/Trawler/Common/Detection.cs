using System;
namespace Trawler.Common
{
	public class Detection
	{
        public string Name { get; set; }

        public Risk Risk { get; set; } = Risk.None;

        public string Source { get; set; }

        public string Technique { get; set; }

        public object Meta { get; set; }
	}
}

