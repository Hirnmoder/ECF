using NSec.Cryptography;

namespace ECF.Core.Container
{
	public class CSX25519AesGcmEd25519Sha512 : CSX25519AesGcmEd25519ShaX
	{
		internal override uint Identifier => 0x01010102u;

		public CSX25519AesGcmEd25519Sha512()
			: base(HashAlgorithm.Sha512)
		{
		}
	}
}