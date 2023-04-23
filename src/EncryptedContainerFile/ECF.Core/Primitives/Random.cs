using System;
using System.Security.Cryptography;

namespace ECF.Core.Primitives
{
    internal static class Random
    {
        internal static void FillRandom(this Span<byte> data)
            => RandomNumberGenerator.Fill(data);

        internal static int Uniform(int fromInclusive, int toExclusive)
            => RandomNumberGenerator.GetInt32(fromInclusive, fromInclusive >= toExclusive ? fromInclusive + 1 : toExclusive);
    }
}
