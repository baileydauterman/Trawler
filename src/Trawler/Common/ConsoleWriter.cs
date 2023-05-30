namespace Trawler.Common
{
	public class ConsoleWriter
	{
		public static void WriteMessage(LogLevel level, string message)
		{
			switch (level)
			{
				case LogLevel.None:
					Write($"[%] {message}");
                    break;

                case LogLevel.Info:
					Write($"[+] {message}", ConsoleColor.White);
					break;

				case LogLevel.Warning:
					Write($"[!] {message}", ConsoleColor.Yellow);
					break;

				case LogLevel.Error:
					Write($"[!] {message}", ConsoleColor.Red);
					break;

				default:
					Console.WriteLine(message);
					break;
			}
		}

		public static void Write(string message, ConsoleColor color = ConsoleColor.Gray)
		{
			Console.ForegroundColor = color;
			Console.WriteLine(message);
			Console.ForegroundColor = ConsoleColor.White;
		}

		/// <summary>
		/// uses + prefix and gray console color
		/// </summary>
		/// <param name="message"></param>
		public static void WriteInfo(string message) => WriteMessage(LogLevel.Info, message);

		/// <summary>
		/// uses ! prefix and yellow console color
		/// </summary>
		/// <param name="message"></param>
        public static void WriteWarning(string message) => WriteMessage(LogLevel.Warning, message);

		/// <summary>
		/// uses ! prefix and Red console color
		/// </summary>
		/// <param name="message"></param>
        public static void WriteError(string message) => WriteMessage(LogLevel.Error, message);
    }
}