using CommandLine;

namespace ECF.CLI.Arguments
{
    internal enum CLICipherSuite
    {
        X25519_AESGCM_ED25519_SHA256,
        X25519_AESGCM_ED25519_SHA512,
    }

    [Verb("create", aliases: new[] {"c"}, HelpText = "Create a new encrypted container file")]
    internal class CreateArgument : FileOperationArgumentBase
    {
        // ToDo: Support more Algorithms
        [Option("cipher-suite", Default = CLICipherSuite.X25519_AESGCM_ED25519_SHA512, Required = false, HelpText = "Cipher Suite to use")]
        public CLICipherSuite CipherSuite { get; set; }

        // ToDo: Support multiple Content Types (Key-Value-Store, Plain Text, Blob, ...)
    }
}
