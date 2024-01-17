using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("add-recipient", HelpText = "Add a recipient to an existing Encrypted Container File")]
    internal class AddRecipientArgument : FileOperationArgumentBase
    {
        [Option('r', "recipient", Required = true, HelpText = "Recipient Public Key File")]
        public string RecipientPKFile { get; protected set; }

        [Option("allow-duplicate-names", Required = false, Default = false, HelpText = "Allow adding a recipient whose name is already present in the recipient list.")]
        public bool AllowDuplicateNames { get; protected set; }
    }
}
