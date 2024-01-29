using NSec.Cryptography;

namespace ECF.Core.Container
{
    public class CSX25519Ed25519AegisSha256 : CSX25519Ed25519AegisShaX
    {
        internal override uint Identifier => 0x01010201u;

        public CSX25519Ed25519AegisSha256()
            : base(HashAlgorithm.Sha256)
        {
        }
    }
}
