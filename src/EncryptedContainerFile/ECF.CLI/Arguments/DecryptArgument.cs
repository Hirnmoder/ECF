using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("decrypt", aliases: new[] {"d"}, HelpText = "Decrypt an Encrypted Container File")]
    internal class DecryptArgument : FileOperationArgumentBase
    {
        // ToDo: Support multiple decryption options based on Content Type
    }
}
