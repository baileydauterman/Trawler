using System.Runtime.InteropServices;
using System.Security.Principal;
using Trawler.Common;
using Trawler.Constants;

namespace Trawler;
class Program
{
    static void Main(string[] args)
    {
        Strings.WriteHeader();
        ConsoleWriter.WriteInfo("Hello World");
        ConsoleWriter.WriteWarning("Hello World");
        ConsoleWriter.WriteError("Hello World");
        ConsoleWriter.WriteMessage(LogLevel.None, "Hello World");

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            ConsoleWriter.WriteError("Trawler is designed for Windows");
            return;
        }

        if (!IsAmin())
        {
            ConsoleWriter.WriteError("Trawler should be run as admin to ensure the best experience");
        }

        var trawlerContext = new TrawlerContext(args[0], args[1]);
    }

    private static bool IsAmin()
    {
        return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
             .IsInRole(WindowsBuiltInRole.Administrator);
    }
}