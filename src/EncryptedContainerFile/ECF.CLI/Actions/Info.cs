using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Primitives;
using System;
using System.IO;
using System.Text;

namespace ECF.CLI.Actions
{
    internal static class Info
    {
        internal static readonly Func<InfoArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(InfoArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                using var fs = File.OpenRead(arg.Filepath);
                using var ec = EncryptedContainer.Load(fs, k);

                Console.WriteLine($"Information about file {arg.Filepath}");
                Console.WriteLine($"Container Version:     {ec.ContainerVersion}");
                Console.WriteLine($"Cipher Suite:          {ec.CipherSuite}");
                Console.WriteLine($"Content Length:        {ec.ContentStream.Length}");
                Console.WriteLine($"Content Type:          {ec.ContentType.FriendlyName}");
                Console.WriteLine($"Recipients:            {ec.Recipients.Length}");

                foreach (var r in ec.Recipients)
                {
                    Console.WriteLine($"  Name:                {r.Name}");
                    Console.WriteLine($"  Public Key:          {r.GetPublicKeyHex()}");
                    Console.WriteLine($"");
                }


                return ExitCode.OK;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return ExitCode.Error;
            }
        }

    }
}
