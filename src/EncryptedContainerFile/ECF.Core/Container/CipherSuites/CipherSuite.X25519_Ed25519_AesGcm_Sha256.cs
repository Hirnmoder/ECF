using NSec.Cryptography;

namespace ECF.Core.Container
{
    public class CSX25519Ed25519AesGcmSha256 : CSX25519Ed25519AesGcmShaX
    {
        internal override uint Identifier => 0x01010101u;

        public CSX25519Ed25519AesGcmSha256()
            : base(HashAlgorithm.Sha256)
        {
        }
    }
}
