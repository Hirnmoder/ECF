using ECF.Core.Container.Recipients;
using ECF.Core.Primitives;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace ECF.Core.Container.Keys
{
    /// <summary>
    /// Represents an asymmetric key used for encryption, decryption, signing and verifying.
    /// </summary>
    public abstract class ECFKey : IDisposable
    {
        private static readonly Dictionary<uint, (Type t,
                                                  Func<FixedMemoryStream, ECFKey> loadFunc,
                                                  Func<uint> getPrivateKeySize,
                                                  Func<AeadAlgorithm, uint> getCiphertextLength)> KeyTypes = new();
        private static readonly Dictionary<uint, AeadAlgorithm> SymEncAlgorithms = new();
        private static readonly Dictionary<uint, ECFKeyPBKDF> PBKDFAlgorithms = new();

        static ECFKey()
        {
            AddECFKeyType<EKX25519Ed25519>();

            AddSymmetricEncryptionAlgorithm(1, AeadAlgorithm.Aes256Gcm);
            AddSymmetricEncryptionAlgorithm(2, AeadAlgorithm.Aegis256);

            AddPBKDFAlgorithm(1, ECFKeyPBKDFArgon2id.Instance);

        }

        /// <summary>
        /// Adds a new key type.
        /// </summary>
        /// <typeparam name="T">Type of the key.</typeparam>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddECFKeyType<T>()
            where T : IECFKey
        {
            var identifier = T.Identifier;
            if (KeyTypes.ContainsKey(identifier))
            {
                throw new InvalidOperationException($"Key type with identifier {identifier} already exists!");
            }
            else if (KeyTypes.Any(kt => kt.Value.t == typeof(T)))
            {
                throw new InvalidOperationException($"Key type {typeof(T)} already exists!");
            }
            else
            {
                KeyTypes.Add(identifier, (typeof(T), T.Load, T.GetPrivateKeySize, a => T.GetCiphertextLength(T.GetPrivateKeySize(), a)));
            }
        }

        /// <summary>
        /// Adds a symmetric encryption algorithm with the specified identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the algorithm.</param>
        /// <param name="algorithm">The symmetric encryption algorithm.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddSymmetricEncryptionAlgorithm(uint identifier, AeadAlgorithm algorithm)
        {
            if (SymEncAlgorithms.ContainsKey(identifier))
                throw new InvalidOperationException($"Symmetric encryption algorithm with identifier {identifier} already exists!");
            if (SymEncAlgorithms.ContainsValue(algorithm))
                throw new InvalidOperationException($"Symmetric encryption algorithm {algorithm} already exists!");
            SymEncAlgorithms.Add(identifier, algorithm);
        }

        /// <summary>
        /// Adds a PBKDF algorithm with the specified identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the algorithm.</param>
        /// <param name="algorithm">The PBKDF algorithm.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddPBKDFAlgorithm(uint identifier, ECFKeyPBKDF algorithm)
        {
            if (PBKDFAlgorithms.ContainsKey(identifier))
                throw new InvalidOperationException($"PBKDF algorithm with identifier {identifier} already exists!");
            if (PBKDFAlgorithms.ContainsValue(algorithm))
                throw new InvalidOperationException($"PBKDF algorithm {algorithm} already exists!");
            PBKDFAlgorithms.Add(identifier, algorithm);
        }

        /// <param name="argon2Parameters">The parameters for the Argon2id algorithm.</param>
        /// <inheritdoc cref="SaveToFile(string, bool, FixedMemoryStream, uint, uint, ECFKeyPBKDF.Configuration)"/>
        public void SaveToFileAes256Argon2id(string filename,
                                             bool overwriteExisting,
                                             FixedMemoryStream password,
                                             Argon2Parameters argon2Parameters)
        {
            this.SaveToFile(filename,
                            overwriteExisting,
                            password,
                            1,
                            1,
                            new ECFKeyPBKDFArgon2id.Argon2idConfiguration(argon2Parameters));
        }

        /// <param name="filename">The file to write the encrypted private key to.</param>
        /// <param name="overwriteExisting">Allows overwriting an existing file.</param>
        /// <inheritdoc cref="Save(Stream, FixedMemoryStream, uint, uint, ECFKeyPBKDF.Configuration)"/>
        public void SaveToFile(string filename,
                               bool overwriteExisting,
                               FixedMemoryStream password,
                               uint symEncAlgIdentifier,
                               uint pbkdfAlgIdentifier,
                               ECFKeyPBKDF.Configuration pbkdfConfiguration)
        {
            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentNullException(nameof(filename));

            if (File.Exists(filename) && !overwriteExisting)
                throw new InvalidOperationException($"File {filename} already exists!");

            using var file = File.Create(filename);
            this.Save(file, password, symEncAlgIdentifier, pbkdfAlgIdentifier, pbkdfConfiguration);
            file.Flush();
            file.Close();
        }

        /// <summary>
        /// Writes a newly created <see cref="ECFKey"/> to a stream encrypted with a password.
        /// Note: This method can only be called for keys that were created using the Create() method.
        /// </summary>
        /// <param name="stream">The stream to write the key to.</param>
        /// <param name="password">The password to protect the key.</param>
        /// <param name="symEncAlgIdentifier">The identifier of the symmetric encryption algorithm to use.</param>
        /// <param name="pbkdfAlgIdentifier">The identifier of the PBKDF algorithm to use.</param>
        /// <param name="pbkdfConfiguration">The configuration for the PBKDF algorithm.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public void Save(Stream stream,
                         FixedMemoryStream password,
                         uint symEncAlgIdentifier,
                         uint pbkdfAlgIdentifier,
                         ECFKeyPBKDF.Configuration pbkdfConfiguration)
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(pbkdfConfiguration);
            if (!stream.CanWrite)
                throw new InvalidOperationException("Stream is not writable!");

            if (!SymEncAlgorithms.TryGetValue(symEncAlgIdentifier, out AeadAlgorithm? symEncAlg))
                throw new InvalidOperationException($"Symmetric encryption algorithm with identifier {symEncAlgIdentifier} not found!");

            if (!PBKDFAlgorithms.TryGetValue(pbkdfAlgIdentifier, out ECFKeyPBKDF? pbkdfAlg))
                throw new InvalidOperationException($"PBKDF algorithm with identifier {pbkdfAlgIdentifier} not found!");

            var keyTypeInfo = KeyTypes.First(kt => kt.Value.t == this.GetType());

            var salt = new byte[pbkdfAlg.SaltLength];
            salt.AsSpan().FillRandom();


            using var associatedDataStream = new FixedMemoryStream();
            using var encryptedPrivateKey = new FixedBytes(keyTypeInfo.Value.getCiphertextLength(symEncAlg));
            using (var symKey = pbkdfAlg.DeriveKey(pbkdfConfiguration, password.GetAsReadOnlySpan(), salt, symEncAlg))
            {
                using var symNonce = new FixedBytes((uint)symEncAlg.NonceSize);
                symNonce.GetDataAsSpan().FillRandom();

                using (var bw = new BinaryWriter(associatedDataStream, Encoding.UTF8, true))
                {
                    bw.Write((uint)1);                          // Version of key file format
                    bw.Write(keyTypeInfo.Key);                  // Identifier of key type
                    bw.Write(symEncAlgIdentifier);              // Identifier of symmetric encryption algorithm
                    bw.Write(pbkdfAlgIdentifier);               // Identifier of PBKDF algorithm
                    bw.Write(salt);                             // Salt used for key derivation
                    bw.Write(symNonce.GetDataAsReadOnlySpan()); // Nonce used for symmetric encryption
                    pbkdfAlg.WriteConfiguration(                // PBKDF configuration
                        bw.BaseStream,
                        pbkdfConfiguration);
                }

                using (var privateKeyStream = new FixedMemoryStream())
                {
                    this.SaveInternal(privateKeyStream);
                    privateKeyStream.Position = 0;
                    // now encrypt the private key
                    symEncAlg.Encrypt(symKey,
                                      symNonce.GetDataAsReadOnlySpan(),
                                      associatedDataStream.GetAsReadOnlySpan(),
                                      privateKeyStream.GetAsReadOnlySpan(),
                                      encryptedPrivateKey.GetDataAsSpan());
                }
            }
            stream.Write(associatedDataStream.GetAsReadOnlySpan());
            stream.Write(encryptedPrivateKey.GetDataAsReadOnlySpan());
        }


        /// <summary>
        /// Loads a <see cref="ECFKey"/> from a file that has been encrypted with a password.
        /// </summary>
        /// <param name="filename">The file to load the key from.</param>
        /// <inheritdoc cref="Load(Stream, FixedMemoryStream)" />
        public static ECFKey Load(string filename, FixedMemoryStream password)
        {
            if (string.IsNullOrWhiteSpace(filename))
                throw new ArgumentNullException(nameof(filename));
            if (!File.Exists(filename))
                throw new InvalidOperationException($"File {filename} does not exist!");

            using var file = File.OpenRead(filename);
            return Load(file, password);
        }

        /// <summary>
        /// Loads a <see cref="ECFKey"/> from a stream that has been encrypted with a password.
        /// </summary>
        /// <param name="stream">The stream to load the key from.</param>
        /// <param name="password">The password that was used to protect the key.</param>
        /// <returns>The loaded key.</returns>
        public static ECFKey Load(Stream stream, FixedMemoryStream password)
        {
            using var br = new BinaryReader(stream, Encoding.UTF8, true);

            var originalPosition = stream.Position; // remember original position
            var version = br.ReadUInt32();
            if (version == 1)
            {
                var keyTypeIdentifier = br.ReadUInt32();
                if (!KeyTypes.TryGetValue(keyTypeIdentifier, out var entry))
                    throw new InvalidOperationException($"Key type with identifier {keyTypeIdentifier} not found!");

                var symEncAlgIdentifier = br.ReadUInt32();
                if (!SymEncAlgorithms.TryGetValue(symEncAlgIdentifier, out var symEncAlg))
                    throw new InvalidOperationException($"Symmetric encryption algorithm with identifier {symEncAlgIdentifier} not found!");

                var pbkdfAlgIdentifier = br.ReadUInt32();
                if (!PBKDFAlgorithms.TryGetValue(pbkdfAlgIdentifier, out var pbkdfAlg))
                    throw new InvalidOperationException($"PBKDF algorithm with identifier {pbkdfAlgIdentifier} not found!");

                var salt = br.ReadBytes((int)pbkdfAlg.SaltLength);
                var symNonce = br.ReadBytes((int)symEncAlg.NonceSize);
                var pbkdfConfiguration = pbkdfAlg.ReadConfiguration(br.BaseStream);

                var bytesRead = stream.Position - originalPosition;
                br.BaseStream.Position = originalPosition; // reset position
                var associatedData = br.ReadBytes((int)bytesRead);

                // Now load the encrypted private key and decrypt it
                var encryptedPrivateKey = br.ReadBytes((int)entry.getCiphertextLength(symEncAlg));
                using var symKey = pbkdfAlg.DeriveKey(pbkdfConfiguration,
                                                       password.GetAsReadOnlySpan(),
                                                       salt,
                                                       symEncAlg);
                using var decryptedPrivateKey = new FixedBytes(entry.getPrivateKeySize());
                if (!symEncAlg.Decrypt(symKey,
                                       symNonce.AsSpan(),
                                       associatedData.AsSpan(),
                                       encryptedPrivateKey.AsSpan(),
                                       decryptedPrivateKey.GetDataAsSpan()))
                    throw new System.Security.Cryptography.CryptographicException("Invalid password or file corrupt!");

                using var decryptedPrivateKeyStream = new FixedMemoryStream(decryptedPrivateKey, false);
                var ecfKey = entry.loadFunc(decryptedPrivateKeyStream);
                Debug.Assert(decryptedPrivateKeyStream.Position == decryptedPrivateKeyStream.Length, "Decrypted private key import did not read to end!");
                return ecfKey;
            }
            else
            {
                throw new InvalidOperationException($"Unsupported key file format version {version}!");
            }
        }

        /// <summary>
        /// Creates a new <see cref="Recipient"/> object based on this key by exporting the public key and signing the recipient name.
        /// </summary>
        /// <param name="cipherSuite">The <see cref="CipherSuite"/> that defines which algorithms to use.</param>
        /// <param name="recipientName">The name of the recipient to sign.</param>
        /// <returns></returns>
        public abstract Recipient ExportAsRecipient(CipherSuite cipherSuite, string recipientName);

        /// <summary>
        /// Gets the public key for this key.
        /// </summary>
        /// <param name="cipherSuite">The <see cref="CipherSuite"/> that defines which algorithms to use.</param>
        /// <returns></returns>
        public abstract PublicKey GetRecipientPublicKey(CipherSuite cipherSuite);

        /// <summary>
        /// Saves the key to a stream which will be encrypted later.
        /// </summary>
        /// <param name="stream">The stream to save the <see cref="ECFKey"/> to.</param>
        protected abstract void SaveInternal(FixedMemoryStream stream);

        /// <summary>
        /// <inheritdoc cref="IDisposable.Dispose"/>
        /// </summary>
        public abstract void Dispose();
    }

    /// <summary>
    /// Represents a key that can be used for encryption, decryption, signing and verifying.
    /// </summary>
    public interface IECFKey
    {
        /// <summary>
        /// The identifier of the key type.
        /// </summary>
        static abstract uint Identifier { get; }

        /// <summary>
        /// Loads the key from a stream which has been decrypted before.
        /// </summary>
        /// <param name="stream">The stream to load the <see cref="ECFKey"/> from.</param>
        static abstract ECFKey Load(FixedMemoryStream stream);

        /// <summary>
        /// Gets the size of the private key in bytes.
        /// </summary>
        /// <returns>Number of bytes of the private key.</returns>
        static abstract uint GetPrivateKeySize();

        /// <summary>
        /// Gets the ciphertext length for the specified plaintext length and algorithm.
        /// </summary>
        /// <param name="plaintextLength">The length of the plaintext.</param>
        /// <param name="algorithm">The encryption algorithm to use.</param>
        /// <returns></returns>
        static virtual uint GetCiphertextLength(uint plaintextLength, AeadAlgorithm algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            return plaintextLength + (uint)(algorithm switch
            {
                Aes256Gcm => algorithm.TagSize,
                Aegis256 => algorithm.TagSize,
                _ => throw new NotImplementedException(),
            });
        }
    }
}
