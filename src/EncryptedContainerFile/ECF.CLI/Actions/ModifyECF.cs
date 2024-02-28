using ECF.CLI.Arguments;
using ECF.Core.Container;
using ECF.Core.Container.Keys;
using System;
using System.Diagnostics;
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

                if (string.IsNullOrWhiteSpace(arg.Editor))
                    ExecuteWithYae(ec, arg);
                else
                    ExecuteWithExternal(ec, arg);

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

        private static void ExecuteWithYae(EncryptedContainer ec, ModifyArgument arg)
        {
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
        }

        private static void ExecuteWithExternal(EncryptedContainer ec, ModifyArgument arg)
        {
            if (OperatingSystem.IsLinux())
            {
                var filename = $"/dev/shm/{Path.GetFileName(arg.Filepath)}-{Guid.NewGuid()}";
                try
                {
                    using var fs = File.Create(filename, 8192, FileOptions.DeleteOnClose);
                    File.SetUnixFileMode(filename, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    fs.Write(ec.ContentStream.GetAsReadOnlySpan());
                    fs.Flush();

                    var ps = Process.Start(arg.Editor!, filename) ?? throw new ApplicationException($"Could not start process {arg.Editor}");
                    ps.WaitForExit();
                    if (ps.ExitCode != 0)
                    {
                        throw new Exception($"External editor exited with code {ps.ExitCode}, which indicates failure. Abort.");
                    }

                    fs.Position = 0;
                    ec.ContentStream.SetLength(0);
                    fs.CopyTo(ec.ContentStream);

                    fs.Close();
                    fs.Dispose();
                }
                finally
                {
                    File.Delete(filename);
                }
            }
            else if (OperatingSystem.IsWindows())
            {
                throw new NotImplementedException($"External editors are currently unsupported on Windows.");
            }
            else
            {
                throw new InvalidOperationException();
            }
        }
    }
}
