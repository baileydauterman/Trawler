using System;
namespace Trawler.Common
{
	public class ConsoleWriter
	{
		public static void WriteMessage(LogLevel level, string message)
		{
			switch (level)
			{
				case LogLevel.None:
					Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine($"[%] {message}");
					Console.ForegroundColor = ConsoleColor.White;
                    break;

                case LogLevel.Info:
					Console.ForegroundColor = ConsoleColor.White;
					Console.WriteLine($"[+] {message}");
					break;

				case LogLevel.Warning:
					Console.ForegroundColor = ConsoleColor.Yellow;
					Console.WriteLine($"[!] {message}");
					Console.ForegroundColor = ConsoleColor.White;
					break;

				case LogLevel.Error:
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine($"[!] {message}");
					Console.ForegroundColor = ConsoleColor.White;
					break;

				default:
					Console.WriteLine(message);
					break;
			}
		}

		public static void WriteInfo(string message) => WriteMessage(LogLevel.Info, message);

        public static void WriteWarning(string message) => WriteMessage(LogLevel.Warning, message);

        public static void WriteError(string message) => WriteMessage(LogLevel.Error, message);
    }
}