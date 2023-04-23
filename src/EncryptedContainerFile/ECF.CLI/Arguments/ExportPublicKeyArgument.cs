using CommandLine;

namespace ECF.CLI.Arguments
{
    [Verb("export-public-key", aliases: new[] { "export-pk" }, HelpText = "Export a public key and save it to file")]
    internal class ExportPublicKeyArgument : NeedsKeyArgumentBase
    {
        [Value(0, Required = true, MetaName = "Public Key File", HelpText = "Filename including path")]
        public string Filepath { get; protected set; } = string.Empty;

        [Option('n', "name", Required = false, Default = "", HelpText = "A string to sign with private key. Usually the name of the key pair holder.")]
        public string Name { get; protected set; }
    }
}
