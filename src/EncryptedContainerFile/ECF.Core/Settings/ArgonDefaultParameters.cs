using NSec.Cryptography;

namespace ECF.Core.Settings
{
    internal class ArgonDefaultParameters
    {
        private static readonly Argon2Parameters DefaultArgon2Parameters = new()
        {
            DegreeOfParallelism = 1,    // More is currently unsupported
            MemorySize = 2048 * 1024,   // 2048 MiB
            NumberOfPasses = 5,
        };

        internal static Argon2Parameters Get()
            => DefaultArgon2Parameters;
    }
}
