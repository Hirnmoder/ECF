using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Container.Keys;
using System;
using System.IO;
using System.Text;

namespace ECF.CLI.Actions
{
    internal static class DecryptECF
    {
        internal static readonly Func<DecryptArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(DecryptArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                using var fs = File.OpenRead(arg.Filepath);
                using var ec = EncryptedContainer.Load(fs, k);

                using var sr = new StreamReader(ec.ContentStream, Encoding.UTF8, leaveOpen: true);
                Console.WriteLine(sr.ReadToEnd());
                sr.Close();

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
