using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Primitives;
using System;
using System.IO;
using System.Text;

namespace ECF.CLI.Actions
{
    internal static class Util
    {
        internal static FixedMemoryStream PromptPassword(string prompt = "Please enter password: ")
        {
            Console.Write(prompt);
            var fc = new FixedMemoryStream();
            using var sw = new StreamWriter(fc, new UnicodeEncoding(false, false), leaveOpen: true);
            int i = 0;
            while (true)
            {
                var k = Console.ReadKey(true);
                switch (k.Key)
                {
                    case ConsoleKey.Enter:
                        Console.WriteLine();
                        return fc;
                    case ConsoleKey.Backspace:
                        i = Math.Max(0, i - 1) * sizeof(char);
                        fc.Position = i; // Go back first time
                        sw.Write('\0'); // Overwrite character
                        fc.SetLength(i); // Go back second time
                        break;
                    default:
                        sw.Write(k.KeyChar);
                        i++;
                        break;
                }
            }
        }

        internal static string Prompt(string prompt)
        {
            Console.Write(prompt);
            return Console.ReadLine() ?? string.Empty;
        }

        internal static string GetKeyfilename(NeedsKeyArgumentBase arg)
        {
            if (string.IsNullOrWhiteSpace(arg.Keyfile))
            {
                var homeFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.None);
                if (string.IsNullOrWhiteSpace(homeFolder))
                    throw new DirectoryNotFoundException("Cannot locate home folder.");

                return Path.Combine(homeFolder, "ecf.keyfile");
            }
            return arg.Keyfile;
        }

        internal static CipherSuite GetCipherSuite(CLICipherSuite cs)
        {
            return cs switch
            {
                CLICipherSuite.X25519_AESGCM_ED25519_SHA256 => CipherSuite.X25519_AESgcm_Ed25519_Sha256,
                CLICipherSuite.X25519_AESGCM_ED25519_SHA512 => CipherSuite.X25519_AESgcm_Ed25519_Sha512,
                _ => throw new InvalidDataException($"Cipher Suite {cs} not recognized."),
            };
        }
    }
}
