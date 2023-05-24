using System.Runtime.InteropServices;
using System.Security.Principal;
using CommandLine;
using Trawler.Common;
using Trawler.Constants;

namespace Trawler;
class Program
{
    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<CommandLineOptions>(args)
            .WithParsed(RunOptions)
            .WithNotParsed(HandleOptionsError);
    }

    private static void RunOptions(CommandLineOptions opts)
    {
        Strings.WriteHeader();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            ConsoleWriter.WriteError("Trawler is designed for Windows");
            return;
        }

        if (!IsAdmin())
        {
            ConsoleWriter.WriteError("Trawler should be run as admin to ensure the best experience");
        }

        var trawlerContext = new TrawlerContext(opts);
    }

    private static void HandleOptionsError(IEnumerable<Error> errs)
    {
        foreach (var err in errs)
        {
            if (err.Tag != ErrorType.BadFormatConversionError)
            {
                continue;
            }

            ConsoleWriter.WriteWarning("Selected unavailable scan option. Available options are:");

            foreach (var opt in Enum.GetValues<ScanOptions>())
            {
                ConsoleWriter.WriteInfo($"\t{opt}");
            }
        }
    }


    private static bool IsAdmin()
        => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
}