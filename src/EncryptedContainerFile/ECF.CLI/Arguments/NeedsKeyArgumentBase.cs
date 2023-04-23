using CommandLine;

namespace ECF.CLI.Arguments
{
    internal abstract class NeedsKeyArgumentBase : ArgumentBase
    {
        [Option('k', "keyfile", Default = null, HelpText = "Use a custom private key file.")]
        public string? Keyfile { get; protected set; }
    }
}
