using CommandLine;

namespace ECF.CLI.Arguments
{
    internal abstract class FileOperationArgumentBase : NeedsKeyArgumentBase
    {
        [Value(0, Required = true, MetaName = "Encrypted Container File", HelpText = "Filename including path.")]
        public string Filepath { get; protected set; } = string.Empty;
    }
}
