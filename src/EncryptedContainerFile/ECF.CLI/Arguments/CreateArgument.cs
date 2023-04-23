using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("create", aliases: new[] {"c"}, HelpText = "Create a new encrypted container file")]
    internal class CreateArgument : FileOperationArgumentBase
    {
        // ToDo: Support multiple Algorithms
        // ToDo: Support multiple Content Types (Key-Value-Store, Plain Text, Blob, ...)
    }
}
