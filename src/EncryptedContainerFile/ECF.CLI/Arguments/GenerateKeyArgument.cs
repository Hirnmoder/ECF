using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("generate", aliases: new[] { "g", "gen" }, HelpText = "Generate a key pair for hybrid encryption and save it to file")]
    internal class GenerateKeyArgument : NeedsKeyArgumentBase
    {
        [Option("overwrite", Default = false, Required = false, HelpText = "Overwrite an existing key file.")]
        public bool Overwrite { get; protected set; }
    }
}
