using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("add-recipient", HelpText = "Add a recipient to an existing Encrypted Container File")]
    internal class AddRecipientArgument : FileOperationArgumentBase
    {
        [Option('r', "recipient", Required = true, HelpText = "Recipient Public Key File")]
        public string RecipientPKFile { get; protected set; }
    }
}
