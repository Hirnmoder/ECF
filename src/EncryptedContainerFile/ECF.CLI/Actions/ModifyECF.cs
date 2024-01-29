using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Container.Keys;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Yae.Core;

namespace ECF.CLI.Actions
{
    internal static class ModifyECF
    {
        internal static readonly Func<ModifyArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(ModifyArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                using var fs = File.Open(arg.Filepath, FileMode.Open, FileAccess.ReadWrite);
                using var ec = EncryptedContainer.Load(fs, k);

                using var sr = new StreamReader(ec.ContentStream, Encoding.UTF8, leaveOpen: true);
                using var sw = new StreamWriter(ec.ContentStream, Encoding.UTF8, leaveOpen: true);
                Task.Run(async () =>
                {
                    var te = new TextEditor(arg.Filepath, sr, () =>
                    {
                        sw.Flush();
                        sw.BaseStream.Position = 0;
                        sw.BaseStream.SetLength(0);
                        return sw;
                    }, 30);
                    await te.RunAsync();
                }).Wait();
                sr.Close();
                sw.Close();

                fs.SetLength(0); // Reset stream length
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
