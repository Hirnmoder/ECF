using ECF.Core.Primitives;
using NSec.Cryptography;
using System;
using System.Diagnostics;
using System.IO;

namespace ECF.Core.Container
{
    public abstract class CSX25519AesGcmEd25519ShaX : CipherSuite
    {
        private const int SHARED_SECRET_LENGTH = 32; // Curve25519 Point

        internal override int KeyAgreementInfoSize => KAI_X25519_AesGcm_Ed25519_ShaX.Size;

        internal CSX25519AesGcmEd25519ShaX(HashAlgorithm hashAlgorithm)
            : base(KeyAgreementAlgorithm.X25519, AeadAlgorithm.Aes256Gcm, SignatureAlgorithm.Ed25519, hashAlgorithm)
        { }

        internal override Key GetSymmetricKey(ECFKey privateKey, KeyAgreementInfo keyAgreementInfo)
        {
            if (keyAgreementInfo is not KAI_X25519_AesGcm_Ed25519_ShaX kai)
                throw new EncryptedContainerException($"Expected {nameof(KeyAgreementInfo)} of type {nameof(KAI_X25519_AesGcm_Ed25519_ShaX)}. Got {keyAgreementInfo}.");

            var sk = privateKey.X25519PrivateKey;

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
            Debug.Assert(hash.Length >= kai.XorMaskForAesKey.Length);

            sharedSecretConcatWithPublicKeys.Clear();

            for (int i = 0; i < kai.XorMaskForAesKey.Length; i++)
                hash[i] ^= kai.XorMaskForAesKey[i];

            Debug.Assert(hash.Length >= this.SymmetricEncryptionAlgorithm.KeySize);

            var k = Key.Import(this.SymmetricEncryptionAlgorithm, hash[..this.SymmetricEncryptionAlgorithm.KeySize], KeyBlobFormat.RawSymmetricKey, new() { ExportPolicy = KeyExportPolicies.None });
            hash.Clear();
            return k;
        }

        internal override KeyAgreementInfo GetKeyAgreementInfo(PublicKey publicKey, Key symmetricKey)
        {
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
            Debug.Assert(size == AeadAlgorithm.Aes256Gcm.KeySize);

            byte[] xorMask = new byte[AeadAlgorithm.Aes256Gcm.KeySize];
            for (int i = 0; i < xorMask.Length; i++)
                xorMask[i] = (byte)(exportedSymmetricKey[i] ^ hash[i]);

            exportedSymmetricKey.Clear();
            hash.Clear();

            return new KAI_X25519_AesGcm_Ed25519_ShaX(ephemeralPrivateKey.PublicKey, xorMask);
        }

        internal override KeyAgreementInfo GetFakeKeyAgreementInfo()
        {
            var xorMask = new byte[this.SymmetricEncryptionAlgorithm.KeySize];
            xorMask.AsSpan().FillRandom();

            using var ephemeralPrivateKey = Key.Create(this.KeyAgreementAlgorithm, new() { ExportPolicy = KeyExportPolicies.None });

            return new KAI_X25519_AesGcm_Ed25519_ShaX(ephemeralPrivateKey.PublicKey, xorMask);
        }

        internal override KeyAgreementInfoCreator GetKeyAgreementInfoCreator()
            => new KAI_X25519_AesGcm_Ed25519_ShaX.Creator();

        internal override Key GetSigningKey(ECFKey privateKey)
            => privateKey.Ed25519PrivateKey;

        internal override Key GetKeyAgreementKey(ECFKey privateKey)
            => privateKey.X25519PrivateKey;

        internal override Key GetExportKey(ECFKey privateKey)
            => privateKey.Ed25519PrivateKey;

        internal override int GetExportKeySize()
            => this.SignatureAlgorithm.PublicKeySize;

        internal override Algorithm GetExportKeyAlgorithm()
            => this.SignatureAlgorithm;
    }

    internal class KAI_X25519_AesGcm_Ed25519_ShaX : KeyAgreementInfo
    {
        internal static readonly int Size = KeyAgreementAlgorithm.X25519.PublicKeySize + AeadAlgorithm.Aes256Gcm.KeySize;

        internal PublicKey PublicKey { get; }
        internal byte[] XorMaskForAesKey { get; }

        internal KAI_X25519_AesGcm_Ed25519_ShaX(PublicKey publicKey, byte[] xorMaskForAesKey)
        {
            this.PublicKey = publicKey;
            this.XorMaskForAesKey = xorMaskForAesKey;
        }

        internal override void Write(BinaryWriter bw)
        {
            bw.Write(this.PublicKey.Export(KeyBlobFormat.RawPublicKey));
            bw.Write(this.XorMaskForAesKey);
        }

        internal class Creator : KeyAgreementInfoCreator
        {
            internal override KeyAgreementInfo Load(BinaryReader br)
            {
                Span<byte> publicKeyBytes = stackalloc byte[KeyAgreementAlgorithm.X25519.PublicKeySize];
                int amount = br.Read(publicKeyBytes);
                Debug.Assert(amount == KeyAgreementAlgorithm.X25519.PublicKeySize);

                Span<byte> xorMaskBytes = stackalloc byte[AeadAlgorithm.Aes256Gcm.KeySize];
                amount = br.Read(xorMaskBytes);
                Debug.Assert(amount == AeadAlgorithm.Aes256Gcm.KeySize);

                if (!PublicKey.TryImport(KeyAgreementAlgorithm.X25519, publicKeyBytes, KeyBlobFormat.RawPublicKey, out var pk) || pk == null)
                    throw new EncryptedContainerException($"Importing X25519 public key failed.");

                return new KAI_X25519_AesGcm_Ed25519_ShaX(pk, xorMaskBytes.ToArray());
            }
        }
    }
}
