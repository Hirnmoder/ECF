using System.Diagnostics;

namespace ECF.Core.Container
{
    [DebuggerDisplay("{System.Convert.ToHexString(SaltedHash)}")]
    internal sealed class RecipientDecryptionInformation
    {
        internal byte[] SaltedHash { get; }
        internal KeyAgreementInfo KeyAgreementInfo { get; }

        internal RecipientDecryptionInformation(byte[] saltedHash, KeyAgreementInfo keyAgreementInfo)
        {
            this.SaltedHash = saltedHash;
            this.KeyAgreementInfo = keyAgreementInfo;
        }
    }
}