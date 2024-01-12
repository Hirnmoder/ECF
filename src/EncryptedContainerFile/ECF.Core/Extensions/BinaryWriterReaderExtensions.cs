using ECF.Core.Container;
using System.IO;
using System.Text;

namespace ECF.Core.Extensions
{
    internal static class BinaryWriterExtensions
    {
        internal static void WriteECFString(this BinaryWriter bw, string value)
        {
            // 4 bytes length in bytes, then UTF-8
            var bytes = Encoding.UTF8.GetBytes(value);
            bw.Write((uint)bytes.Length);
            bw.Write(bytes);
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
