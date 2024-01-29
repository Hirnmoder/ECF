using NSec.Cryptography;

namespace ECF.Core.Container
{
    public class CSX25519Ed25519AegisSha512 : CSX25519Ed25519AegisShaX
    {
        internal override uint Identifier => 0x01010202u;

        public CSX25519Ed25519AegisSha512()
            : base(HashAlgorithm.Sha512)
        {
        }
    }
}
