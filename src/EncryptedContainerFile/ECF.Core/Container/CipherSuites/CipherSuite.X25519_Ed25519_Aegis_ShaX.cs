using NSec.Cryptography;

namespace ECF.Core.Container
{
    public abstract class CSX25519Ed25519AegisShaX : CSX25519Ed25519Base
    {
        internal CSX25519Ed25519AegisShaX(HashAlgorithm hashAlgorithm)
            : base(AeadAlgorithm.Aegis256, hashAlgorithm)
        { }
    }
}