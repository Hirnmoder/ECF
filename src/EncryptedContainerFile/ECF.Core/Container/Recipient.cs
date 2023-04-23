using ECF.Core.Extensions;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ECF.Core.Container
{
    public sealed class Recipient
    {
        internal PublicKey PublicKey { get; }
        public string Name { get; }
        internal byte[] NameSignature { get; }

        internal Recipient(PublicKey publicKey, string name, byte[] nameSignature)
        {
            this.PublicKey = publicKey;
            this.Name = name;
            this.NameSignature = nameSignature;
        }

        public string GetPublicKeyHex()
        {
            Span<byte> publicKey = stackalloc byte[this.PublicKey.Size];
            this.ExportPublicKey(publicKey);
            return Convert.ToHexString(publicKey);
        }

        /// <summary>
        /// Serializes a <see cref="Recipient"/> object into a stream.
        /// </summary>
        /// <param name="outStream">The <see cref="Stream"/> to write to.</param>
        /// <exception cref="EncryptedContainerException"></exception>
        public void Write(Stream outStream)
        {
            using var bw = new BinaryWriter(outStream, Encoding.UTF8, leaveOpen: true);
            Span<byte> publicKey = stackalloc byte[this.PublicKey.Size];
            this.ExportPublicKey(publicKey);
            bw.Write(publicKey);
            bw.WriteECFString(this.Name);
            bw.Write(this.NameSignature);
            bw.Flush();
            bw.Close();
        }

        internal static Recipient Load(BinaryReader br, CipherSuite cipherSuite, bool verifySignature)
        {
            Span<byte> recipientPublicKey = stackalloc byte[cipherSuite.GetExportKeySize()];

            br.Read(recipientPublicKey);
            if (!PublicKey.TryImport(cipherSuite.GetExportKeyAlgorithm(), recipientPublicKey, KeyBlobFormat.RawPublicKey, out var pk) || pk == default)
                throw new EncryptedContainerException($"Importing recipient's public key failed.");
            var name = br.ReadECFString();
            var signature = new byte[cipherSuite.SignatureAlgorithm.SignatureSize];
            int amount = br.Read(signature.AsSpan());
            Debug.Assert(amount == cipherSuite.SignatureAlgorithm.SignatureSize);
            if (verifySignature)
            {
                if (!cipherSuite.VerifySignature(pk, Encoding.UTF8.GetBytes(name), signature))
                    throw new EncryptedContainerException($"Recipient {name} has an invalid signature.");
            }
            var r = new Recipient(pk, name, signature);
            return r;
        }

        private void ExportPublicKey(Span<byte> publicKey)
        {
            Debug.Assert(publicKey.Length >= this.PublicKey.Size);
            if (!this.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, publicKey, out var size))
                throw new EncryptedContainerException($"Exporting recipient's public key failed.");
            Debug.Assert(size == this.PublicKey.Size);
        }
    }


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
