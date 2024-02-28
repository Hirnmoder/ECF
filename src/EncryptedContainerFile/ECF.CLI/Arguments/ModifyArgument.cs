using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("modify", aliases: new[] { "m" }, HelpText = "Modify the contents of an Encrypted Container File")]
    internal class ModifyArgument : DecryptArgument
    {
        [Option('e', "editor", Default = null, HelpText = "Use an external editor to edit the file.", Required = false)]
        public string? Editor { get; protected set; }
    }
}
