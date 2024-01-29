using ECF.CLI.Arguments;
using System;

namespace ECF.CLI.Actions
{
    internal static class GenerateKey
    {
        internal static readonly Func<GenerateKeyArgument, ExitCode> Execute = ExecuteInternal;
        private static ExitCode ExecuteInternal(GenerateKeyArgument arg)
        {
            try
            {
                using var p = Util.PromptPassword();
                using var p_repeat = Util.PromptPassword("Please repeat password: ");
                if (!p.GetAsReadOnlySpan().SequenceEqual(p_repeat.GetAsReadOnlySpan()))
                {
                    Console.WriteLine("Passwords do not match!");
                    return ExitCode.Error;
                }

                var cs = Util.GetCipherSuite(arg.CipherSuite);
                using var k = cs.CreateECFKey();
                k.SaveToFileAes256Argon2id(Util.GetKeyfilename(arg), arg.Overwrite, p, new()
                {
                    DegreeOfParallelism = 1,
                    MemorySize = arg.MemorySize,
                    NumberOfPasses = arg.Iterations,
                });
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
