using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("generate", aliases: new[] { "g", "gen" }, HelpText = "Generate a key pair for hybrid encryption and save it to file")]
    internal class GenerateKeyArgument : NeedsKeyArgumentBase
    {
        [Option("overwrite", Default = false, Required = false, HelpText = "Overwrite an existing key file.")]
        public bool Overwrite { get; protected set; }

        [Option("cipher-suite", Default = CLICipherSuite.X25519_ED25519_AESGCM_SHA512, Required = false, HelpText = "Cipher Suite to use.")]
        public CLICipherSuite CipherSuite { get; protected set; }

        [Option('m', "memory-size", Default = 512 * 1024, Required = false, HelpText = "Memory size in kilobytes to use for Argon2id.")]
        public int MemorySize { get; protected set; }

        [Option('i', "iterations", Default = 10, Required = false, HelpText = "Number of iterations to use for Argon2id.")]
        public int Iterations { get; protected set; }
    }
}
