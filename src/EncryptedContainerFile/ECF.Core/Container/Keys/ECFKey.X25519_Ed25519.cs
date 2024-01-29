using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using ECF.Core.Container.Recipients;
using ECF.Core.Primitives;
using NSec.Cryptography;

namespace ECF.Core.Container.Keys
{
    /// <summary>
    /// A private Ed25519 and X25519 key that can be saved to and loaded from a file.
    /// </summary>
    public sealed class EKX25519Ed25519 : ECFKey, IECFKey
    {
        internal Key Ed25519PrivateKey { get; }
        internal Key X25519PrivateKey { get; }

        /// <inheritdoc/>
        public static uint Identifier => 0x00000001;

        private EKX25519Ed25519(Key ed25519privateKey)
        {
            this.Ed25519PrivateKey = ed25519privateKey;
            this.X25519PrivateKey = KeyConverter.ConvertPrivateKey(ed25519privateKey, KeyAgreementAlgorithm.X25519);
        }

        /// <summary>
        /// Creates a new <see cref="EKX25519Ed25519"/> based on random initialization.
        /// </summary>
        /// <returns>The newly created <see cref="EKX25519Ed25519"/>.</returns>
        public static EKX25519Ed25519 Create()
        {
            var k = Key.Create(SignatureAlgorithm.Ed25519, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            return new EKX25519Ed25519(k);
        }


        /// <inheritdoc/>
        public override Recipient ExportAsRecipient(CipherSuite cipherSuite, string recipientName)
        {
            ArgumentNullException.ThrowIfNull(cipherSuite);
            if (string.IsNullOrWhiteSpace(recipientName))
                throw new ArgumentNullException(nameof(recipientName));
            if (cipherSuite is not CSX25519Ed25519Base)
                throw new EncryptedContainerException($"Expected cipher suite {nameof(CSX25519Ed25519Base)}, got {cipherSuite}.");

            var nameSignature = new byte[cipherSuite.SignatureAlgorithm.SignatureSize];
            var nameData = Encoding.UTF8.GetBytes(recipientName);
            cipherSuite.Sign(cipherSuite.GetSigningKey(this), nameData, nameSignature);
            var exportPublicKey = this.GetRecipientPublicKey(cipherSuite);
            var recipient = new RX25519Ed25519(exportPublicKey, recipientName, nameSignature);
            return recipient;
        }

        /// <inheritdoc/>
        public override PublicKey GetRecipientPublicKey(CipherSuite cipherSuite)
        {
            ArgumentNullException.ThrowIfNull(cipherSuite);
            if (cipherSuite is not CSX25519Ed25519Base)
                throw new EncryptedContainerException($"Expected cipher suite {nameof(CSX25519Ed25519Base)}, got {cipherSuite}.");
            return this.Ed25519PrivateKey.PublicKey;
        }


        /// <inheritdoc/>
        public override void Dispose()
        {
            this.Ed25519PrivateKey.Dispose();
            this.X25519PrivateKey.Dispose();

        }

        /// <inheritdoc/>
        protected override void SaveInternal(FixedMemoryStream stream)
        {
            using var exportedKey = new FixedBytes(GetPrivateKeySize());
            if (!this.Ed25519PrivateKey.TryExport(KeyBlobFormat.RawPrivateKey, exportedKey.GetDataAsSpan(), out var size))
                throw new Exception("Cannot export private Ed25519 key!");
            Debug.Assert(size == exportedKey.Length, "Exported key size mismatch!");
            stream.Write(exportedKey.GetDataAsReadOnlySpan());
        }

        /// <inheritdoc/>

        public static ECFKey Load(FixedMemoryStream stream)
        {
            Key? ed25519PrivateKey;
            using (var exportedKey = new FixedBytes(GetPrivateKeySize()))
            {
                var amount = stream.Read(exportedKey.GetDataAsSpan());
                Debug.Assert(amount == exportedKey.Length, "Read key size mismatch!");
                if (!Key.TryImport(SignatureAlgorithm.Ed25519,
                                  exportedKey.GetDataAsReadOnlySpan(),
                                  KeyBlobFormat.RawPrivateKey,
                                  out ed25519PrivateKey))
                    throw new Exception("Cannot import private Ed25519 key!");
            }
            Debug.Assert(ed25519PrivateKey != null, "Key not loaded!");
            return new EKX25519Ed25519(ed25519PrivateKey);
        }

        /// <inheritdoc/>
        public static uint GetPrivateKeySize()
        {
            return (uint)SignatureAlgorithm.Ed25519.PrivateKeySize;
        }

    }
}