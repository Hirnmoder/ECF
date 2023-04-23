using CommandLine;
using ECF.CLI.Actions;
using ECF.CLI.Arguments;
using System;

namespace ECF.CLI
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            var parser = new Parser(with =>
            {
                with.AutoHelp = true;
                with.AutoVersion = true;
                with.CaseSensitive = false;
                with.CaseInsensitiveEnumValues = true;
                with.EnableDashDash = false;
                with.HelpWriter = Console.Out;
            });

            var result = parser.ParseArguments<
                  CreateArgument
                , ModifyArgument
                , DecryptArgument
                , GenerateKeyArgument
                , ExportPublicKeyArgument
                , AddRecipientArgument
                , RemoveRecipientArgument
                , InfoArgument
                >(args);

            return (int)result.MapResult(
                CreateECF.Execute,
                ModifyECF.Execute,
                DecryptECF.Execute,
                GenerateKey.Execute,
                ExportPublicKey.Execute,
                AddRecipient.Execute,
                RemoveRecipient.Execute,
                Info.Execute,
                errors => ExitCode.Error);
        }
    }
}