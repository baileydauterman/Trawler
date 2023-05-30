using Trawler.Common;

namespace Trawler.Detectors
{
    internal abstract class Detector : IDetector
    {
        protected Detector(TrawlerContext context, string source)
        {
            Context = context;
            Source = source;
        }

        protected TrawlerContext Context { get; }
        // TODO: figure out abstract stuff

        public string Source { get; }
    }
}
