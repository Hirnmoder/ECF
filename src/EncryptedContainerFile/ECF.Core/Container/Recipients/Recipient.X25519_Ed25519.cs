using ECF.Core.Extensions;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ECF.Core.Container.Recipients
{
    /// <summary>
    /// A recipient using X25519 and Ed25519.
    /// </summary>
    public class RX25519Ed25519 : Recipient, IRecipient
    {
        internal PublicKey PublicKey { get; }


        internal RX25519Ed25519(PublicKey publicKey, string name, byte[] signature)
            : base(name, signature)
        {
            Debug.Assert(publicKey != null, "Public key must not be null.");
            Debug.Assert(publicKey.Algorithm == SignatureAlgorithm.Ed25519, "Public key must be of type Ed25519.");
            this.PublicKey = publicKey;
        }

        /// <inheritdoc />
        public override string GetPublicKeyHex()
        {
            Span<byte> publicKey = stackalloc byte[this.PublicKey.Size];
            this.ExportPublicKey(publicKey);
            return Convert.ToHexString(publicKey);
        }

        /// <inheritdoc />
        public override void Write(Stream outStream)
        {
            using var bw = new BinaryWriter(outStream, Encoding.UTF8, leaveOpen: true);
            Span<byte> publicKey = stackalloc byte[this.PublicKey.Size];
            this.ExportPublicKey(publicKey);
            bw.Write(publicKey);
            bw.WriteECFString(this.Name);
            bw.Write(this.Signature);
            bw.Flush();
            bw.Close();
        }

        /// <inheritdoc />
        public static Recipient Load(BinaryReader br, CipherSuite cipherSuite, bool verifySignature)
        {
            ArgumentNullException.ThrowIfNull(br);
            ArgumentNullException.ThrowIfNull(cipherSuite);
            if (cipherSuite is not CSX25519Ed25519Base)
                throw new EncryptedContainerException($"Expected cipher suite {nameof(CSX25519Ed25519Base)}, got {cipherSuite}.");

            Span<byte> recipientPublicKey = stackalloc byte[cipherSuite.SignatureAlgorithm.PublicKeySize];

            br.Read(recipientPublicKey);
            if (!PublicKey.TryImport(cipherSuite.SignatureAlgorithm, recipientPublicKey, KeyBlobFormat.RawPublicKey, out var pk) || pk == default)
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
            var r = new RX25519Ed25519(pk, name, signature);
            return r;
        }

        private void ExportPublicKey(Span<byte> publicKey)
        {
            Debug.Assert(publicKey.Length >= this.PublicKey.Size);
            if (!this.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, publicKey, out var size))
                throw new EncryptedContainerException($"Exporting recipient's public key failed.");
            Debug.Assert(size == this.PublicKey.Size);
        }

        /// <inheritdoc />
        public override bool ComparePublicKey(PublicKey publicKey)
        {
            ArgumentNullException.ThrowIfNull(publicKey);
            if (publicKey.Algorithm != SignatureAlgorithm.Ed25519)
                return false;
            return this.PublicKey.Equals(publicKey);
        }

        /// <inheritdoc />
        public override bool ComparePublicKey(Recipient other)
        {
            ArgumentNullException.ThrowIfNull(other);
            if (other is not RX25519Ed25519 r)
                return false;
            return this.ComparePublicKey(r.PublicKey);
        }
    }
}