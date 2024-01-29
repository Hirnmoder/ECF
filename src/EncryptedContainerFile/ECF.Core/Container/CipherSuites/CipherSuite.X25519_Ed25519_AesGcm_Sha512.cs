using NSec.Cryptography;

namespace ECF.Core.Container
{
	public class CSX25519Ed25519AesGcmSha512 : CSX25519Ed25519AesGcmShaX
	{
		internal override uint Identifier => 0x01010102u;

		public CSX25519Ed25519AesGcmSha512()
			: base(HashAlgorithm.Sha512)
		{
		}
	}
}