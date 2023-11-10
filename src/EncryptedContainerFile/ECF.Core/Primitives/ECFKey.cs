using ECF.Core.Container;
using ECF.Core.Settings;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ECF.Core.Primitives
{
    /// <summary>
    /// A private Ed25519 and X25519 key that can be saved to and loaded from a file.
    /// </summary>
    public sealed class ECFKey : IDisposable
    {
        private const int SALT_NONCE_LENGTH = 16;
        private const KeyBlobFormat KEY_FORMAT = KeyBlobFormat.NSecPrivateKey;
        private static readonly AeadAlgorithm SymEncAlg = AeadAlgorithm.Aes256Gcm;

        internal Key Ed25519PrivateKey { get; }
        internal Key X25519PrivateKey { get; }

        private ECFKey(Key ed25519privateKey)
        {
            this.Ed25519PrivateKey = ed25519privateKey;
            this.X25519PrivateKey = KeyConverter.ConvertPrivateKey(ed25519privateKey, KeyAgreementAlgorithm.X25519);
        }

        /// <summary>
        /// Creates a new <see cref="ECFKey"/> based on random initialization.
        /// </summary>
        /// <returns>The newly created <see cref="ECFKey"/>.</returns>
        public static ECFKey Create()
        {
            var k = Key.Create(SignatureAlgorithm.Ed25519, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            return new ECFKey(k);
        }

        /// <summary>
        /// Loads a file containing an encrypted Ed25519 private key.
        /// </summary>
        /// <param name="filename">The file containing the encrypted private key.</param>
        /// <param name="password">The password to decrypt the key.</param>
        /// <returns>A new <see cref="ECFKey"/> object containing the loaded key.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException"></exception>
        public static ECFKey Load(string filename, FixedMemoryStream password)
        {
            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentNullException(nameof(filename));

            if (!File.Exists(filename))
                throw new FileNotFoundException($"File not found: {filename}");

            var fileContent = new ReadOnlySpan<byte>(File.ReadAllBytes(filename));
            var saltNonce = fileContent[..SALT_NONCE_LENGTH];
            var aesNonce = fileContent[SALT_NONCE_LENGTH..(SALT_NONCE_LENGTH + SymEncAlg.NonceSize)];
            var encryptedEd25519Key = fileContent[(SALT_NONCE_LENGTH + SymEncAlg.NonceSize)..];

            using var aesKey = GetAesKey(saltNonce, password);

            Span<byte> decryptedEd25519Key = stackalloc byte[encryptedEd25519Key.Length - SymEncAlg.TagSize];
            if (!SymEncAlg.Decrypt(aesKey, aesNonce, null, encryptedEd25519Key, decryptedEd25519Key))
                throw new System.Security.Cryptography.CryptographicException("Invalid password!");

            var key = Key.Import(SignatureAlgorithm.Ed25519, decryptedEd25519Key, KEY_FORMAT, new() { ExportPolicy = KeyExportPolicies.None });

            return new ECFKey(key);
        }

        /// <summary>
        /// Writes a newly created <see cref="ECFKey"/> to a file encrypting the Ed25519 private key with a password.
        /// Note: This method can only be called for keys that were created using <see cref="Create"/>.
        /// </summary>
        /// <param name="filename">The file to write the encrypted private key to.</param>
        /// <param name="password">The password to protect the private key.</param>
        /// <param name="overwriteExisting">Allows overwriting an existing file.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="Exception"></exception>
        public void SaveToFile(string filename, FixedMemoryStream password, bool overwriteExisting)
        {
            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentNullException(nameof(filename));

            if (File.Exists(filename) && !overwriteExisting)
                throw new InvalidOperationException($"File {filename} already exists!");


            using var saltNonceFixed = new FixedBytes(SALT_NONCE_LENGTH);
            var saltNonce = saltNonceFixed.GetDataAsSpan();
            saltNonce.FillRandom();

            using var aesKey = GetAesKey(saltNonce, password);

            var size = this.Ed25519PrivateKey.GetExportBlobSize(KEY_FORMAT);
            Debug.Assert(size > 0);
            using var ed25519PrivateKey = new FixedBytes((uint)size);
            if (!this.Ed25519PrivateKey.TryExport(KEY_FORMAT, ed25519PrivateKey.GetDataAsSpan(), out var blobSize))
                throw new Exception("Cannot export private Ed25519 key!");
            Debug.Assert(blobSize == size);

            using var aesNonceFixed = new FixedBytes((uint)SymEncAlg.NonceSize);
            var aesNonce = aesNonceFixed.GetDataAsSpan();
            aesNonce.FillRandom();

            var encryptedEd25519PrivateKey = new FixedBytes((uint)(ed25519PrivateKey.Length + SymEncAlg.TagSize));
            SymEncAlg.Encrypt(aesKey, aesNonce, null, ed25519PrivateKey.GetDataAsReadOnlySpan(), encryptedEd25519PrivateKey.GetDataAsSpan());

            using var file = File.Create(filename);
            file.Write(saltNonce);
            file.Write(aesNonce);
            file.Write(encryptedEd25519PrivateKey.GetDataAsReadOnlySpan());
            file.Flush();
            file.Close();
        }

        public Recipient ExportAsRecipient(CipherSuite cipherSuite, string name)
        {
            var nameSignature = new byte[cipherSuite.SignatureAlgorithm.SignatureSize];
            var nameData = Encoding.UTF8.GetBytes(name);
            cipherSuite.Sign(cipherSuite.GetSigningKey(this), nameData, nameSignature);
            var recipient = new Recipient(this.ExportPublicKey(cipherSuite), name, nameSignature);
            return recipient;
        }

        public PublicKey ExportPublicKey(CipherSuite cipherSuite)
        {
            return cipherSuite.GetExportKey(this).PublicKey;
        }


        private static FixedBytes GetSalt(ReadOnlySpan<byte> saltNonce)
        {
            var saltHashAlgorithm = HashAlgorithm.Sha256;

            var saltPre1 = Encoding.UTF8.GetBytes($"SaltFor{Environment.UserName}_and_random_nonce_");
            using var saltPre = new FixedBytes((uint)(saltPre1.Length + SALT_NONCE_LENGTH));
            saltPre.CopyFrom(saltPre1, 0);
            saltPre.CopyFrom(saltNonce, saltPre1.Length);

            var salt = new FixedBytes((uint)saltHashAlgorithm.HashSize);
            saltHashAlgorithm.Hash(saltPre.GetDataAsReadOnlySpan(), salt.GetDataAsSpan());
            return salt;
        }

        private static Key GetAesKey(ReadOnlySpan<byte> saltNonce, FixedMemoryStream password)
        {
            using var salt = GetSalt(saltNonce);

            var argon = PasswordBasedKeyDerivationAlgorithm.Argon2id(ArgonDefaultParameters.Get());
            var pwSpan = password.GetAsReadOnlySpan();
            var aesKey = argon.DeriveKey(pwSpan, salt.GetDataAsReadOnlySpan().Slice(0, argon.MaxSaltSize), AeadAlgorithm.Aes256Gcm);

            return aesKey;
        }

        /// <summary>
        /// <inheritdoc cref="IDisposable.Dispose"/>
        /// </summary>
        public void Dispose()
        {
            this.Ed25519PrivateKey.Dispose();
            this.X25519PrivateKey.Dispose();
        }
    }
}
