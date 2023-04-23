using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Primitives;
using System;
using System.IO;
using System.Text;

namespace ECF.CLI.Actions
{
    internal static class CreateECF
    {
        internal static readonly Func<CreateArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(CreateArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                var cs = Util.GetCipherSuite(arg.CipherSuite);
                using var ec = EncryptedContainer.Create(cs, ContentType.Blob);
                ec.AddRecipientFromPrivateKey(k, Environment.UserName);

                using var sw = new StreamWriter(ec.ContentStream, Encoding.UTF8, leaveOpen: true);
                sw.Write("This is a demo text");
                sw.Flush();
                sw.Close();

                using var fs = File.Create(arg.Filepath);
                ec.Write(fs);
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
