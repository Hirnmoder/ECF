using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Container.Keys;
using System;
using System.IO;

namespace ECF.CLI.Actions
{
    internal static class RemoveRecipient
    {
        internal static readonly Func<RemoveRecipientArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(RemoveRecipientArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var k = ECFKey.Load(Util.GetKeyfilename(arg), p);

                using var fsECread = File.OpenRead(arg.Filepath);

                using var ec = EncryptedContainer.Load(fsECread, k);

                if (!string.IsNullOrWhiteSpace(arg.RecipientPKFile))
                {
                    using var fsRread = File.OpenRead(arg.RecipientPKFile);

                    fsECread.Close();
                    fsECread.Dispose();

                    ec.RemoveRecipientFromExport(fsRread);
                    fsRread.Close();
                    fsRread.Dispose();
                }
                else if (!string.IsNullOrWhiteSpace(arg.RecipientName))
                {
                    ec.RemoveRecipient(arg.RecipientName);
                }
                else
                {
                    throw new ArgumentException("Either 'Recipient Public Key File' or  'Recipient Name' must be set!");
                }

                if (!ec.IsECFKeyRecipient(k))
                {
                    throw new InvalidOperationException("You cannot remove yourself from an ECF!");
                }

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
