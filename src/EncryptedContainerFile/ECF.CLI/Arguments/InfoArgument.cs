using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("info", aliases: new[] { "i" }, HelpText = "Displays information about an Encrypted Container File")]
    internal class InfoArgument : FileOperationArgumentBase
    {
    }
}
