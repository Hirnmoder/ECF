using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("remove-recipient", HelpText = "Remove a recipient from an existing Encrypted Container File")]
    internal class RemoveRecipientArgument : FileOperationArgumentBase
    {
        [Option('r', "recipient", Group = "Source", HelpText = "Recipient Public Key File")]
        public string RecipientPKFile { get; protected set; }

        [Option('n', "name", Group = "Source", HelpText = "Recipient Name")]
        public string RecipientName { get; protected set; }

    }
}
