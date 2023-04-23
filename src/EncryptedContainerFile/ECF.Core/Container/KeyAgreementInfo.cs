using System.IO;

namespace ECF.Core.Container
{
    internal abstract class KeyAgreementInfo
    {
        internal abstract void Write(BinaryWriter bw);
    }

    internal abstract class KeyAgreementInfoCreator
    {
        internal abstract KeyAgreementInfo Load(BinaryReader br);
    }
}
