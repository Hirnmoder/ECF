using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Container.Keys;
using System;
using System.IO;

namespace ECF.CLI.Actions
{
    internal static class AddRecipient
    {
        internal static readonly Func<AddRecipientArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(AddRecipientArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                using var fsECread = File.OpenRead(arg.Filepath);
                using var fsRread = File.OpenRead(arg.RecipientPKFile);

                using var ec = EncryptedContainer.Load(fsECread, k);
                fsECread.Close();
                fsECread.Dispose();

                ec.AddRecipientFromExport(fsRread, arg.AllowDuplicateNames);
                fsRread.Close();
                fsRread.Dispose();

                using var fsECwrite = File.Create(arg.Filepath);
                ec.Write(fsECwrite);
                fsECwrite.Flush();
                fsECwrite.Close();
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
