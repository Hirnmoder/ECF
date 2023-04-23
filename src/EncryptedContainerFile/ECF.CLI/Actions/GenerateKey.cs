using ECF.CLI.Arguments;
using ECF.Core.Primitives;
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

                using var k = ECFKey.Create();
                k.SaveToFile(Util.GetKeyfilename(arg), p, arg.Overwrite);
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
