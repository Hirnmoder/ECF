using ECF.Core.Primitives;
using ECF.Core.Container.Keys;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using ECF.Core.Container.Recipients;

namespace ECF.Core.Container
{
    public abstract class CSX25519Ed25519Base : CipherSuite
    {
        private const int SHARED_SECRET_LENGTH = 32; // Curve25519 Point

        internal override int KeyAgreementInfoSize { get; }

        internal CSX25519Ed25519Base(AeadAlgorithm symmetricEncryptionAlgorithm, HashAlgorithm hashAlgorithm)
            : base(KeyAgreementAlgorithm.X25519, SignatureAlgorithm.Ed25519, symmetricEncryptionAlgorithm, hashAlgorithm)
        {
            this.KeyAgreementInfoSize = KeyAgreementAlgorithm.X25519.PublicKeySize + symmetricEncryptionAlgorithm.KeySize;
        }

        internal override uint GetPlaintextLength(uint ciphertextLength)
        {
            if (ciphertextLength < this.SymmetricEncryptionAlgorithm.TagSize)
                throw new EncryptedContainerException($"Encrypted data is shorter than the tag size");
            return (uint)(ciphertextLength - this.SymmetricEncryptionAlgorithm.TagSize);
        }

        internal override uint GetCiphertextLength(uint plaintextLength)
        {
            return plaintextLength + (uint)this.SymmetricEncryptionAlgorithm.TagSize;
        }

        internal override Key GetSymmetricKey(ECFKey privateKey, KeyAgreementInfo keyAgreementInfo)
        {
            if (keyAgreementInfo is not KAI_X25519_Ed25519_Base kai)
                throw new EncryptedContainerException($"Expected {nameof(KeyAgreementInfo)} of type {nameof(KAI_X25519_Ed25519_Base)}. Got {keyAgreementInfo}.");

            var sk = this.GetKeyAgreementKey(privateKey);

            Debug.Assert(sk.Algorithm == this.KeyAgreementAlgorithm);
            Debug.Assert(kai.PublicKey.Algorithm == this.KeyAgreementAlgorithm);

            using var ss = this.AgreeOnKey(sk, kai.PublicKey, KeyExportPolicies.AllowPlaintextExport);
            if (ss == null)
                throw new EncryptedContainerException($"Retrieving encryption information failed.");
            Debug.Assert(ss.GetExportBlobSize(SharedSecretBlobFormat.RawSharedSecret) == SHARED_SECRET_LENGTH);

            Span<byte> sharedSecretConcatWithPublicKeys = stackalloc byte[SHARED_SECRET_LENGTH + 2 * KeyAgreementAlgorithm.X25519.PublicKeySize];
            if (!ss.TryExport(SharedSecretBlobFormat.RawSharedSecret, sharedSecretConcatWithPublicKeys, out var size))
                throw new EncryptedContainerException($"Exporting shared secret failed.");
            Debug.Assert(size == SHARED_SECRET_LENGTH);

            var pkMeSlice = sharedSecretConcatWithPublicKeys[SHARED_SECRET_LENGTH..(SHARED_SECRET_LENGTH + KeyAgreementAlgorithm.X25519.PublicKeySize)];
            var pkOtherSlice = sharedSecretConcatWithPublicKeys[(SHARED_SECRET_LENGTH + KeyAgreementAlgorithm.X25519.PublicKeySize)..];

            Debug.Assert(pkOtherSlice.Length == KeyAgreementAlgorithm.X25519.PublicKeySize);
            Debug.Assert(pkMeSlice.Length == KeyAgreementAlgorithm.X25519.PublicKeySize);

            if (!sk.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, pkMeSlice, out size))
                throw new EncryptedContainerException($"Exporting own public key failed.");
            Debug.Assert(size == KeyAgreementAlgorithm.X25519.PublicKeySize);

            if (!kai.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, pkOtherSlice, out size))
                throw new EncryptedContainerException($"Exporting other public key failed.");
            Debug.Assert(size == KeyAgreementAlgorithm.X25519.PublicKeySize);

            Span<byte> hash = stackalloc byte[this.HashAlgorithm.HashSize];
            this.Hash(sharedSecretConcatWithPublicKeys, hash);
            Debug.Assert(hash.Length >= kai.XorMaskForSymmetricKey.Length);

            sharedSecretConcatWithPublicKeys.Clear();

            for (int i = 0; i < kai.XorMaskForSymmetricKey.Length; i++)
                hash[i] ^= kai.XorMaskForSymmetricKey[i];

            Debug.Assert(hash.Length >= this.SymmetricEncryptionAlgorithm.KeySize);

            var k = Key.Import(this.SymmetricEncryptionAlgorithm, hash[..this.SymmetricEncryptionAlgorithm.KeySize], KeyBlobFormat.RawSymmetricKey, new() { ExportPolicy = KeyExportPolicies.None });
            hash.Clear();
            return k;
        }

        internal override KeyAgreementInfo GetKeyAgreementInfo(Recipient recipient, Key symmetricKey)
        {
            if (recipient is not RX25519Ed25519 r)
                throw new EncryptedContainerException($"Expected {nameof(Recipient)} of type {nameof(RX25519Ed25519)}. Got {recipient}.");

            var publicKey = r.PublicKey;
            if (publicKey.Algorithm == this.SignatureAlgorithm)
            {
                publicKey = KeyConverter.ConvertPublicKey(publicKey, this.KeyAgreementAlgorithm);
            }

            Debug.Assert(publicKey.Algorithm == this.KeyAgreementAlgorithm);
            Debug.Assert(symmetricKey.Algorithm == this.SymmetricEncryptionAlgorithm);

            using var ephemeralPrivateKey = Key.Create(this.KeyAgreementAlgorithm, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            using var ss = this.AgreeOnKey(ephemeralPrivateKey, publicKey, KeyExportPolicies.AllowPlaintextExport);
            if (ss == null)
                throw new EncryptedContainerException($"Creating encryption information failed.");
            Debug.Assert(ss.GetExportBlobSize(SharedSecretBlobFormat.RawSharedSecret) == SHARED_SECRET_LENGTH);

            Span<byte> sharedSecretConcatWithPublicKeys = stackalloc byte[SHARED_SECRET_LENGTH + 2 * KeyAgreementAlgorithm.X25519.PublicKeySize];
            if (!ss.TryExport(SharedSecretBlobFormat.RawSharedSecret, sharedSecretConcatWithPublicKeys, out var size))
                throw new EncryptedContainerException($"Exporting shared secret failed.");
            Debug.Assert(size == SHARED_SECRET_LENGTH);

            var pkOtherSlice = sharedSecretConcatWithPublicKeys[SHARED_SECRET_LENGTH..(SHARED_SECRET_LENGTH + KeyAgreementAlgorithm.X25519.PublicKeySize)];
            var pkMeSlice = sharedSecretConcatWithPublicKeys[(SHARED_SECRET_LENGTH + KeyAgreementAlgorithm.X25519.PublicKeySize)..];

            Debug.Assert(pkOtherSlice.Length == KeyAgreementAlgorithm.X25519.PublicKeySize);
            Debug.Assert(pkMeSlice.Length == KeyAgreementAlgorithm.X25519.PublicKeySize);

            if (!publicKey.TryExport(KeyBlobFormat.RawPublicKey, pkOtherSlice, out size))
                throw new EncryptedContainerException($"Exporting own public key failed.");
            Debug.Assert(size == KeyAgreementAlgorithm.X25519.PublicKeySize);

            if (!ephemeralPrivateKey.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, pkMeSlice, out size))
                throw new EncryptedContainerException($"Exporting other public key failed.");
            Debug.Assert(size == KeyAgreementAlgorithm.X25519.PublicKeySize);

            Span<byte> hash = stackalloc byte[this.HashAlgorithm.HashSize];
            this.Hash(sharedSecretConcatWithPublicKeys, hash);
            Debug.Assert(hash.Length >= this.SymmetricEncryptionAlgorithm.KeySize);

            sharedSecretConcatWithPublicKeys.Clear();

            Span<byte> exportedSymmetricKey = stackalloc byte[symmetricKey.Size];
            if (!symmetricKey.TryExport(KeyBlobFormat.RawSymmetricKey, exportedSymmetricKey, out size))
                throw new EncryptedContainerException($"Exporting symmetric key failed.");
            Debug.Assert(size == this.SymmetricEncryptionAlgorithm.KeySize);

            byte[] xorMask = new byte[this.SymmetricEncryptionAlgorithm.KeySize];
            for (int i = 0; i < xorMask.Length; i++)
                xorMask[i] = (byte)(exportedSymmetricKey[i] ^ hash[i]);

            exportedSymmetricKey.Clear();
            hash.Clear();

            return new KAI_X25519_Ed25519_Base(ephemeralPrivateKey.PublicKey, xorMask);
        }

        internal override KeyAgreementInfo GetFakeKeyAgreementInfo()
        {
            var xorMask = new byte[this.SymmetricEncryptionAlgorithm.KeySize];
            xorMask.AsSpan().FillRandom();

            using var ephemeralPrivateKey = Key.Create(this.KeyAgreementAlgorithm, new() { ExportPolicy = KeyExportPolicies.None });

            return new KAI_X25519_Ed25519_Base(ephemeralPrivateKey.PublicKey, xorMask);
        }

        internal override KeyAgreementInfoCreator GetKeyAgreementInfoCreator()
            => new KAI_X25519_Ed25519_Base.Creator(this.SymmetricEncryptionAlgorithm);

        internal override Key GetSigningKey(ECFKey privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey);
            if (privateKey is not EKX25519Ed25519 pk)
                throw new EncryptedContainerException($"Expected {nameof(ECFKey)} of type {nameof(EKX25519Ed25519)}. Got {privateKey}.");
            return pk.Ed25519PrivateKey;
        }

        internal override Key GetKeyAgreementKey(ECFKey privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey);
            if (privateKey is not EKX25519Ed25519 pk)
                throw new EncryptedContainerException($"Expected {nameof(ECFKey)} of type {nameof(EKX25519Ed25519)}. Got {privateKey}.");
            return pk.X25519PrivateKey;
        }

        internal override Recipient LoadRecipient(BinaryReader br, bool verifySignature)
        {
            return RX25519Ed25519.Load(br, this, verifySignature);
        }

        internal override PublicKey GetIdentificationTagKey(ECFKey privateKey)
        {
            if (privateKey is not EKX25519Ed25519 pk)
                throw new EncryptedContainerException($"Expected {nameof(ECFKey)} of type {nameof(EKX25519Ed25519)}. Got {privateKey}.");
            return pk.Ed25519PrivateKey.PublicKey;
        }

        internal override PublicKey GetIdentificationTagKey(Recipient recipient)
        {
            if (recipient is not RX25519Ed25519 r)
                throw new EncryptedContainerException($"Expected {nameof(Recipient)} of type {nameof(RX25519Ed25519)}. Got {recipient}.");
            return r.PublicKey;
        }

        /// <inheritdoc/>
        public override ECFKey CreateECFKey()
        {
            return EKX25519Ed25519.Create();
        }
    }

    internal class KAI_X25519_Ed25519_Base : KeyAgreementInfo
    {
        internal PublicKey PublicKey { get; }
        internal byte[] XorMaskForSymmetricKey { get; }

        internal KAI_X25519_Ed25519_Base(PublicKey publicKey, byte[] xorMaskForSymmetricKey)
        {
            this.PublicKey = publicKey;
            this.XorMaskForSymmetricKey = xorMaskForSymmetricKey;
        }

        internal override void Write(BinaryWriter bw)
        {
            bw.Write(this.PublicKey.Export(KeyBlobFormat.RawPublicKey));
            bw.Write(this.XorMaskForSymmetricKey);
        }

        internal class Creator : KeyAgreementInfoCreator
        {
            protected int SymmetricKeyLength { get; }

            internal Creator(AeadAlgorithm symmetricEncryptionAlgorithm)
            {
                this.SymmetricKeyLength = symmetricEncryptionAlgorithm.KeySize;
            }

            internal override KeyAgreementInfo Load(BinaryReader br)
            {
                Span<byte> publicKeyBytes = stackalloc byte[KeyAgreementAlgorithm.X25519.PublicKeySize];
                int amount = br.Read(publicKeyBytes);
                Debug.Assert(amount == KeyAgreementAlgorithm.X25519.PublicKeySize);

                Span<byte> xorMaskBytes = stackalloc byte[this.SymmetricKeyLength];
                amount = br.Read(xorMaskBytes);
                Debug.Assert(amount == this.SymmetricKeyLength);

                if (!PublicKey.TryImport(KeyAgreementAlgorithm.X25519, publicKeyBytes, KeyBlobFormat.RawPublicKey, out var pk) || pk == null)
                    throw new EncryptedContainerException($"Importing X25519 public key failed.");

                return new KAI_X25519_Ed25519_Base(pk, xorMaskBytes.ToArray());
            }
        }
    }
}