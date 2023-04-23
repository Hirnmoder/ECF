using NSec.Cryptography;

namespace ECF.Core.Container
{
    public class CSX25519AesGcmEd25519Sha256 : CSX25519AesGcmEd25519ShaX
    {
        internal override uint Identifier => 0x01010101u;

        public CSX25519AesGcmEd25519Sha256()
            : base(HashAlgorithm.Sha256)
        {
        }
    }
}
