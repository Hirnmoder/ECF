using NSec.Cryptography;

namespace ECF.Core.Container
{
    public abstract class CSX25519Ed25519AesGcmShaX : CSX25519Ed25519Base
    {
        internal CSX25519Ed25519AesGcmShaX(HashAlgorithm hashAlgorithm)
            : base(AeadAlgorithm.Aes256Gcm, hashAlgorithm)
        { }
    }
}
