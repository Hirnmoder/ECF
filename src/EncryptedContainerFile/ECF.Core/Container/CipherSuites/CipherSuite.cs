using ECF.Core.Container.Keys;
using ECF.Core.Container.Recipients;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;

namespace ECF.Core.Container
{
    public abstract class CipherSuite
    {
        public static readonly CSX25519Ed25519AesGcmSha256 X25519_Ed25519_AesGcm_Sha256 = new();
        public static readonly CSX25519Ed25519AesGcmSha512 X25519_Ed25519_AesGcm_Sha512 = new();

        public static readonly CSX25519Ed25519AegisSha256 X25519_Ed25519_Aegis_Sha256 = new();
        public static readonly CSX25519Ed25519AegisSha512 X25519_Ed25519_Aegis_Sha512 = new();

        private static readonly CipherSuite[] CipherSuites;

        internal KeyAgreementAlgorithm KeyAgreementAlgorithm { get; }
        internal SignatureAlgorithm SignatureAlgorithm { get; }
        internal AeadAlgorithm SymmetricEncryptionAlgorithm { get; }
        internal HashAlgorithm HashAlgorithm { get; }
        internal abstract uint Identifier { get; }

        internal abstract int KeyAgreementInfoSize { get; }

        protected private CipherSuite(KeyAgreementAlgorithm keyAgreementAlgorithm, SignatureAlgorithm signatureAlgorithm, AeadAlgorithm symmetricEncryptionAlgorithm, HashAlgorithm hashAlgorithm)
        {
            this.KeyAgreementAlgorithm = keyAgreementAlgorithm;
            this.SignatureAlgorithm = signatureAlgorithm;
            this.SymmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
            this.HashAlgorithm = hashAlgorithm;
        }

        static CipherSuite()
        {
            var definedCipherSuiteFields = typeof(CipherSuite).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            var list = new List<CipherSuite>();
            foreach (var dcsf in definedCipherSuiteFields)
                if (dcsf.FieldType.IsSubclassOf(typeof(CipherSuite)))
                    list.Add((CipherSuite)dcsf.GetValue(null)!);
            CipherSuites = list.ToArray();
        }

        internal static CipherSuite GetCipherSuite(uint identifier)
        {
            foreach (var cs in CipherSuites)
                if (cs.Identifier == identifier)
                    return cs;
            throw new EncryptedContainerException($"CipherSuite with identifier {identifier} not found!");
        }

        internal virtual SharedSecret? AgreeOnKey(Key privateKey, PublicKey otherPartyPublicKey, KeyExportPolicies exportPolicy = KeyExportPolicies.None)
            => this.KeyAgreementAlgorithm.Agree(privateKey, otherPartyPublicKey, new() { ExportPolicy = exportPolicy });

        internal abstract Key GetSymmetricKey(ECFKey privateKey, KeyAgreementInfo keyAgreementInfo);

        internal abstract KeyAgreementInfo GetKeyAgreementInfo(Recipient recipient, Key symmetricKey);

        internal abstract KeyAgreementInfo GetFakeKeyAgreementInfo();

        internal abstract KeyAgreementInfoCreator GetKeyAgreementInfoCreator();

        internal virtual void Encrypt(Key symmetricKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
            => this.SymmetricEncryptionAlgorithm.Encrypt(symmetricKey, nonce, associatedData, plaintext, ciphertext);

        internal virtual bool Decrypt(Key symmetricKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
            => this.SymmetricEncryptionAlgorithm.Decrypt(symmetricKey, nonce, associatedData, ciphertext, plaintext);

        internal abstract uint GetPlaintextLength(uint ciphertextLength);

        internal abstract uint GetCiphertextLength(uint plaintextLength);

        internal virtual void Hash(ReadOnlySpan<byte> data, Span<byte> hash)
            => this.HashAlgorithm.Hash(data, hash);

        internal virtual bool VerifyHash(ReadOnlySpan<byte> data, ReadOnlySpan<byte> hash)
            => this.HashAlgorithm.Verify(data, hash);

        internal virtual void Sign(Key privateKey, ReadOnlySpan<byte> data, Span<byte> signature)
            => this.SignatureAlgorithm.Sign(privateKey, data, signature);

        internal virtual bool VerifySignature(PublicKey publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => this.SignatureAlgorithm.Verify(publicKey, data, signature);

        internal abstract Key GetSigningKey(ECFKey privateKey);

        internal abstract Key GetKeyAgreementKey(ECFKey privateKey);

        internal abstract Recipient LoadRecipient(BinaryReader br, bool verifySignature);

        internal abstract PublicKey GetIdentificationTagKey(ECFKey privateKey);

        internal abstract PublicKey GetIdentificationTagKey(Recipient recipient);

        /// <summary>
        /// Creates a new <see cref="ECFKey"/> for this <see cref="CipherSuite"/>.
        /// </summary>
        /// <returns>The newly created <see cref="ECFKey"/>.</returns>
        public abstract ECFKey CreateECFKey();
    }
}
