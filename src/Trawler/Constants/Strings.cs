using System;
namespace Trawler.Constants
{
    public class Strings
    {
        public const string Logo = @"
    __________  ___ _       ____    __________ 
   /_  __/ __ \/   | |     / / /   / ____/ __ \
    / / / /_/ / /| | | /| / / /   / __/ / /_/ /
   / / / _, _/ ___ | |/ |/ / /___/ /___/ _, _/ 
  /_/ /_/ |_/_/  |_|__/|__/_____/_____/_/ |_|  
      ";
        public const string Title = "Trawler - Dredging Windows for Persistence";
        public const string Link = "https://github.com/joeavanzato/trawler";

        public static void WriteHeader()
        {
            Console.WriteLine(Logo, ConsoleColor.White);
            Console.WriteLine(Title, ConsoleColor.White);
            Console.WriteLine(Link, ConsoleColor.Gray);
            Console.WriteLine();
        }
    }
}

