using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Primitives;
using System;
using System.IO;

namespace ECF.CLI.Actions
{
    internal class ExportPublicKey
    {
        internal static readonly Func<ExportPublicKeyArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(ExportPublicKeyArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                var name = arg.Name;
                while (string.IsNullOrWhiteSpace(name))
                    name = Util.Prompt("Please enter a string to sign (usually the name of the key pair holder): ");

                var exported = k.ExportAsRecipient(CipherSuite.X25519_AESgcm_Ed25519_Sha256, name);
                using var fs = File.Create(arg.Filepath);
                exported.Write(fs);
                fs.Flush();
                fs.Close();
                
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
