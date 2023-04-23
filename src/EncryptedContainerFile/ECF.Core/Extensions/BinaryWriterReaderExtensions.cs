using ECF.Core.Container;
using System.IO;
using System.Text;

namespace ECF.Core.Extensions
{
    internal static class BinaryWriterExtensions
    {
        internal static void WriteECFString(this BinaryWriter bw, string value)
        {
            // 4 bytes length, then UTF-8
            bw.Write((uint)value.Length);
            bw.Write(Encoding.UTF8.GetBytes(value));
        }
    }

    internal static class BinaryReaderExtensions
    {
        internal static string ReadECFString(this BinaryReader br)
        {
            // 4 bytes length, then UTF-8
            uint len = br.ReadUInt32();
            if (len < 0 || len >= int.MaxValue)
                throw new EncryptedContainerException($"String length {len} must not be negative.");
            return Encoding.UTF8.GetString(br.ReadBytes((int)len));
        }
    }
}
