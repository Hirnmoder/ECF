using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("modify", aliases: new[] { "m" }, HelpText = "Modify the contents of an Encrypted Container File")]
    internal class ModifyArgument : DecryptArgument
    {
    }
}
