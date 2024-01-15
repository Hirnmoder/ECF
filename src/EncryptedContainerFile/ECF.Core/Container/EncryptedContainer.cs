using ECF.Core.Primitives;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ECF.Core.Container
{
    public sealed partial class EncryptedContainer : IDisposable
    {
        private const uint DUMMY_VALUE = 0xDEADBEEF;
        private const uint MAGIC_VALUE = 0xECFFC0DE; // Encrypted Container File Format Code

        private List<Recipient> InternalRecipients { get; }

        public ContainerVersion ContainerVersion { get; }
        public CipherSuite CipherSuite { get; }
        public Recipient[] Recipients => this.InternalRecipients.ToArray();
        public ContentType ContentType { get; }

        public FixedMemoryStream ContentStream { get; private set; }

        private EncryptedContainer(ContainerVersion containerVersion, CipherSuite cipherSuite, ContentType contentType)
        {
            this.CipherSuite = cipherSuite;
            this.ContainerVersion = containerVersion;
            this.InternalRecipients = new();
            this.ContentStream = new(1);
            this.ContentType = contentType;
        }


        public static EncryptedContainer Create(CipherSuite cipherSuite, ContentType contentType)
        {
            var ec = new EncryptedContainer(ContainerVersion.Version_1_0, cipherSuite, contentType);
            return ec;
        }

        public void AddRecipientFromPrivateKey(ECFKey privateKey, string name)
        {
            var recipient = privateKey.ExportAsRecipient(this.CipherSuite, name);
            this.AddRecipient(recipient);
        }

        public void AddRecipientFromExport(Stream inStream)
        {
            using var br = new BinaryReader(inStream, Encoding.UTF8, leaveOpen: true);
            var recipient = Recipient.Load(br, this.CipherSuite, true);
            this.AddRecipient(recipient);
        }

        public void RemoveRecipientFromExport(Stream inStream)
        {
            using var br = new BinaryReader(inStream, Encoding.UTF8, leaveOpen: true);
            var recipient = Recipient.Load(br, this.CipherSuite, true);
            this.RemoveRecipient(recipient.PublicKey);
        }

        public void RemoveRecipient(string name)
        {
            var recipients = this.InternalRecipients.FindAll(r => r.Name == name);
            if (recipients.Count == 0)
                throw new EncryptedContainerException($"Recipient with name {name} does not exist!");
            if (recipients.Count > 1)
                throw new EncryptedContainerException($"Multiple Recipients with name {name} exist!");
            this.RemoveRecipient(recipients[0].PublicKey);
        }

        public bool IsECFKeyRecipient(ECFKey privateKey)
        {
            var pk = privateKey.ExportPublicKey(this.CipherSuite);
            return this.InternalRecipients.Exists(r => r.PublicKey.Equals(pk));
        }

        public void Write(Stream outStream, bool addFakeRecipients = true)
        {
            if (this.ContainerVersion != ContainerVersion.Version_1_0)
                throw new EncryptedContainerException($"Invalid Container Version {this.ContainerVersion}.");

            long posForPublicHeaderLength,
                 posForPrivateLength;

            using var symmetricKey = Key.Create(this.CipherSuite.SymmetricEncryptionAlgorithm, new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            Span<byte> symmetricNonce = stackalloc byte[this.CipherSuite.SymmetricEncryptionAlgorithm.NonceSize];
            symmetricNonce.FillRandom();

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.UTF8, true);

            #region Public Header
            bw.Write((uint)this.ContainerVersion);
            bw.Write(this.CipherSuite.Identifier);

            posForPublicHeaderLength = bw.BaseStream.Position;
            bw.Write(DUMMY_VALUE);

            posForPrivateLength = bw.BaseStream.Position;
            bw.Write(DUMMY_VALUE);

            uint mRecipients = (uint)this.InternalRecipients.Count + (addFakeRecipients ? (uint)Primitives.Random.Uniform(8, this.InternalRecipients.Count + 1) : 0);
            bw.Write(mRecipients);

            Span<byte> recipientSalt = stackalloc byte[FieldLengthInfo.RECIPIENT_SALT];
            recipientSalt.FillRandom();
            bw.Write(recipientSalt);

            bw.Write(symmetricNonce);

            var rdis = new List<RecipientDecryptionInformation>();
            foreach (var recipient in this.InternalRecipients)
            {
                var rdi = GetRecipientDecryptionInformation(recipient, this.CipherSuite, symmetricKey, recipientSalt);
                Debug.Assert(rdi.SaltedHash.Length == FieldLengthInfo.RECIPIENT_SALTED_HASH);
                rdis.Add(rdi);
            }

            for (int i = this.InternalRecipients.Count; i < mRecipients; i++)
            {
                var rdi = GetFakeRecipientDecryptionInformation(this.CipherSuite);
                Debug.Assert(rdi.SaltedHash.Length == FieldLengthInfo.RECIPIENT_SALTED_HASH);
                rdis.Add(rdi);
            }

            // Obfuscate which RDI-blocks are real and which are fake
            // + make Loading more efficient (binary tree search) [not implemented yet]
            rdis.Sort((a, b) => a.SaltedHash.AsSpan().SequenceCompareTo(b.SaltedHash));
            Debug.Assert(rdis.Count == mRecipients);
            foreach (var rdi in rdis)
            {
                bw.Write(rdi.SaltedHash);
                long prePos = bw.BaseStream.Position;
                rdi.KeyAgreementInfo.Write(bw);
                Debug.Assert(bw.BaseStream.Position == prePos + this.CipherSuite.KeyAgreementInfoSize);
            }

            WriteAt(bw, posForPublicHeaderLength, (uint)bw.BaseStream.Position);
            #endregion


            #region Private
            long posPrivateBegin = bw.BaseStream.Position;

            // Calculate Hash over Public Header
            // Field "PrivateLength" has no valid value yet -> substitute with magic number
            WriteAt(bw, posForPrivateLength, MAGIC_VALUE);
            Span<byte> hash = stackalloc byte[this.CipherSuite.HashAlgorithm.HashSize];
            this.CipherSuite.Hash(ms.ToArray(), hash);
            this.WritePrivate(bw.BaseStream, symmetricKey, symmetricNonce, hash);

            long posPrivateEnd = bw.BaseStream.Position;
            Debug.Assert(posPrivateEnd >= posPrivateBegin);
            WriteAt(bw, posForPrivateLength, (uint)(posPrivateEnd - posPrivateBegin));
            #endregion

            #region Hash
            // Lastly calculate Hash over everything and append it

            this.CipherSuite.Hash(ms.ToArray(), hash);
            bw.Write(hash);
            #endregion

            // Now flush everything into outStream
            ms.WriteTo(outStream);
            bw.Close();
            ms.Close();

            static void WriteAt(BinaryWriter bw, long pos, uint value)
            {
                long currentPos = bw.BaseStream.Position;
                bw.BaseStream.Position = pos;
                bw.Write(value);
                bw.BaseStream.Position = currentPos;
            }
        }

        public static EncryptedContainer Load(Stream inStream, ECFKey privateKey, bool verifySignatureOfEveryRecipient = true)
        {
            using var br = new BinaryReader(inStream, Encoding.UTF8, true);
            long origPos = br.BaseStream.Position;
            var bytes = new byte[br.BaseStream.Length - br.BaseStream.Position].AsSpan();
            int amount = br.Read(bytes);
            Debug.Assert(amount == bytes.Length);
            br.BaseStream.Position = origPos;

            // Load metadata
            var version = (ContainerVersion)br.ReadUInt32();
            if (version == ContainerVersion.Version_1_0)
            {
                var cipherSuiteIdentifier = br.ReadUInt32();
                var cipherSuite = CipherSuite.GetCipherSuite(cipherSuiteIdentifier);

                // Now check if hash is correct
                int hashLen = cipherSuite.HashAlgorithm.HashSize;
                Span<byte> fileHash = bytes[^hashLen..];
                if (!cipherSuite.VerifyHash(bytes[..^hashLen], fileHash))
                    throw new EncryptedContainerException($"Calculated hash and file hash do not match.");

                uint publicHeaderLength = br.ReadUInt32();
                Debug.Assert((uint)publicHeaderLength != DUMMY_VALUE);
                long posForPrivateLength = br.BaseStream.Position - origPos;
                uint privateLength = br.ReadUInt32();
                Debug.Assert(privateLength != DUMMY_VALUE);
                Debug.Assert(privateLength != MAGIC_VALUE);

                if (bytes.Length < publicHeaderLength + privateLength + cipherSuite.HashAlgorithm.HashSize)
                    throw new EncryptedContainerException($"Container file is too short.");

                uint nRecipients = br.ReadUInt32();
                if (nRecipients <= 0)
                    throw new EncryptedContainerException($"The number of recipients must be a positive integer.");

                Span<byte> recipientSalt = stackalloc byte[FieldLengthInfo.RECIPIENT_SALT];
                amount = br.Read(recipientSalt);
                Debug.Assert(amount == FieldLengthInfo.RECIPIENT_SALT);

                Span<byte> symmetricNonce = stackalloc byte[cipherSuite.SymmetricEncryptionAlgorithm.NonceSize];
                amount = br.Read(symmetricNonce);
                Debug.Assert(amount == cipherSuite.SymmetricEncryptionAlgorithm.NonceSize);

                Span<byte> mySaltedHash = stackalloc byte[cipherSuite.HashAlgorithm.HashSize];
                GetSaltedHash(privateKey.Ed25519PrivateKey.PublicKey, recipientSalt, cipherSuite, mySaltedHash);
                var mySaltedHashToSearch = mySaltedHash[..FieldLengthInfo.RECIPIENT_SALTED_HASH];

                KeyAgreementInfo? kai = default;
                for (int i = 0; i < nRecipients; i++)
                {
                    if (mySaltedHashToSearch.SequenceEqual(br.ReadBytes(FieldLengthInfo.RECIPIENT_SALTED_HASH)))
                    {
                        if (kai != default)
                            throw new EncryptedContainerException($"Given ECFKey is a recipient multiple times.");

                        // Found my recipient decryption info
                        var creator = cipherSuite.GetKeyAgreementInfoCreator();
                        long prePos = br.BaseStream.Position;
                        kai = creator.Load(br);
                        Debug.Assert(br.BaseStream.Position == prePos + cipherSuite.KeyAgreementInfoSize);
                    }
                    else
                    {
                        // Did not find my recipient decryption info
                        // -> Skip n bytes (n = KeyAgreementInfoSize)
                        br.BaseStream.Position += cipherSuite.KeyAgreementInfoSize;
                    }
                }
                if (kai == default)
                    throw new EncryptedContainerException($"Given ECFKey is not a recipient.");

                if (br.BaseStream.Position - origPos != publicHeaderLength)
                    throw new EncryptedContainerException($"Container has an invalid public header length specified.");

                using var symmetricKey = cipherSuite.GetSymmetricKey(privateKey, kai);
                if (symmetricKey == default)
                    throw new EncryptedContainerException($"Retrieving symmetric encryption key failed.");

                // Calculate Hash over Public Header with magic number for field "PrivateLength"
                var publicHeaderBytes = bytes[..(int)(br.BaseStream.Position - origPos)];
                var magicBytes = BitConverter.GetBytes(MAGIC_VALUE);
                Debug.Assert(magicBytes.Length == FieldLengthInfo.PRIVATE_LENGTH);
                for (int i = 0; i < magicBytes.Length; i++)
                    publicHeaderBytes[(int)posForPrivateLength + i] = magicBytes[i];

                return LoadPrivate(bytes[(int)publicHeaderLength..(int)(publicHeaderLength + privateLength)], version, cipherSuite, publicHeaderBytes, symmetricKey, symmetricNonce, verifySignatureOfEveryRecipient);
            }
            else
            {
                throw new EncryptedContainerException($"Container Version {version} not recognized.");
            }
        }


        private static RecipientDecryptionInformation GetRecipientDecryptionInformation(Recipient recipient, CipherSuite cipherSuite, Key symmetricKey, ReadOnlySpan<byte> salt)
        {
            var kai = cipherSuite.GetKeyAgreementInfo(recipient.PublicKey, symmetricKey);

            Span<byte> saltedHash = stackalloc byte[cipherSuite.HashAlgorithm.HashSize];
            GetSaltedHash(recipient.PublicKey, salt, cipherSuite, saltedHash);
            return new RecipientDecryptionInformation(saltedHash[..FieldLengthInfo.RECIPIENT_SALTED_HASH].ToArray(), kai);
        }

        private static RecipientDecryptionInformation GetFakeRecipientDecryptionInformation(CipherSuite cipherSuite)
        {
            var kai = cipherSuite.GetFakeKeyAgreementInfo();
            var saltedHash = new byte[FieldLengthInfo.RECIPIENT_SALTED_HASH];
            saltedHash.AsSpan().FillRandom();
            return new RecipientDecryptionInformation(saltedHash, kai);
        }

        private static void GetSaltedHash(PublicKey publicKey, ReadOnlySpan<byte> salt, CipherSuite cipherSuite, Span<byte> saltedHash)
        {
            Span<byte> preHash = stackalloc byte[publicKey.Size + salt.Length];
            if (!publicKey.TryExport(KeyBlobFormat.RawPublicKey, preHash, out var size))
                throw new EncryptedContainerException($"Exporting public key failed.");
            Debug.Assert(size == publicKey.Size);
            salt.CopyTo(preHash[publicKey.Size..]);
            cipherSuite.Hash(preHash, saltedHash);
        }


        private void WritePrivate(Stream outStream, Key symmetricKey, ReadOnlySpan<byte> symmetricNonce, ReadOnlySpan<byte> publicHeaderHash)
        {
            Debug.Assert(publicHeaderHash.Length == this.CipherSuite.HashAlgorithm.HashSize);

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.UTF8, true);

            bw.Write(this.ContentType.Identifier);
            bw.Write(publicHeaderHash);

            int nRecipientsPrivate = this.InternalRecipients.Count;
            bw.Write(nRecipientsPrivate);
            foreach (var recipient in this.InternalRecipients)
            {
                recipient.Write(bw.BaseStream);
                Debug.Assert(recipient.NameSignature.Length == this.CipherSuite.SignatureAlgorithm.SignatureSize);
            }

            bw.Write((uint)this.ContentStream.Length);
            this.ContentStream.Position = 0;
            this.ContentStream.CopyTo(ms);

            Span<byte> privateHash = stackalloc byte[this.CipherSuite.HashAlgorithm.HashSize];
            using var privateFixedPreHash = new FixedBytes((uint)ms.Length);
            privateFixedPreHash.CopyFrom(ms.GetBuffer(), 0);
            this.CipherSuite.Hash(privateFixedPreHash.GetDataAsReadOnlySpan(), privateHash);
            privateFixedPreHash.Dispose();
            bw.Write(privateHash);

            // Now encrypt the whole private part
            var privateLength = (uint)ms.Length;
            using var privateFixed = new FixedBytes(privateLength);
            privateFixed.CopyFrom(ms.GetBuffer(), 0);
            bw.Close();
            ms.Close();
            ms.Dispose();
            Span<byte> privateEncrypted = new byte[privateLength + this.CipherSuite.SymmetricEncryptionAlgorithm.TagSize];
            this.CipherSuite.Encrypt(symmetricKey, symmetricNonce, privateFixed.GetDataAsReadOnlySpan(), privateEncrypted);
            privateFixed.Dispose();

            outStream.Write(privateEncrypted);
        }

        private static EncryptedContainer LoadPrivate(ReadOnlySpan<byte> encryptedData, ContainerVersion version, CipherSuite cipherSuite, ReadOnlySpan<byte> publicHeaderBytes, Key symmetricKey, ReadOnlySpan<byte> symmetricNonce, bool verifySignatureOfEveryRecipient)
        {
            int amount;

            uint decryptedLength = cipherSuite.GetPlaintextLength((uint)encryptedData.Length);
            using var privateDecrypted = new FixedBytes(decryptedLength);
            if (!cipherSuite.Decrypt(symmetricKey, symmetricNonce, encryptedData, privateDecrypted.GetDataAsSpan()))
                throw new EncryptedContainerException($"Decryption with symmetric key failed.");

            using var ms = new FixedMemoryStream(privateDecrypted, false);
            using var br = new BinaryReader(ms, Encoding.UTF8, true);

            var contentTypeIdentifier = br.ReadUInt32();
            var contentType = ContentType.GetContentType(contentTypeIdentifier);
            var ec = new EncryptedContainer(version, cipherSuite, contentType);

            // Now check if hash is correct
            Span<byte> fileHash = privateDecrypted.GetDataAsSpan().Slice((int)br.BaseStream.Position, cipherSuite.HashAlgorithm.HashSize);
            if (!cipherSuite.VerifyHash(publicHeaderBytes, fileHash))
                throw new EncryptedContainerException($"Calculated hash of public header and encrypted file hash do not match.");
            br.BaseStream.Position += cipherSuite.HashAlgorithm.HashSize;

            uint nRecipientsPrivate = br.ReadUInt32();
            if (nRecipientsPrivate <= 0)
                throw new EncryptedContainerException($"The number of recipients must be a positive integer.");

            for (uint i = 0; i < nRecipientsPrivate; i++)
            {
                var r = Recipient.Load(br, cipherSuite, verifySignatureOfEveryRecipient);
                ec.AddRecipient(r);
            }

            uint contentLength = br.ReadUInt32();
            if (contentLength < 0)
                throw new EncryptedContainerException($"The length of the content must be a positive integer or zero.");

            var content = new FixedBytes(contentLength);
            amount = br.Read(content.GetDataAsSpan());
            ec.ContentStream = new(content);
            Debug.Assert(amount == contentLength);

            fileHash = privateDecrypted.GetDataAsSpan().Slice((int)br.BaseStream.Position, cipherSuite.HashAlgorithm.HashSize);
            if (!cipherSuite.VerifyHash(privateDecrypted.GetDataAsReadOnlySpan().Slice(0, (int)br.BaseStream.Position), fileHash))
                throw new EncryptedContainerException($"Calculated hash of decrypted data and file hash do not match.");
            privateDecrypted.Dispose();

            if (br.BaseStream.Position + cipherSuite.HashAlgorithm.HashSize != decryptedLength)
                throw new EncryptedContainerException($"Did not read to end.");

            br.Close();
            ms.Close();
            return ec;
        }

        private void AddRecipient(Recipient recipient)
        {
            var existingRecipient = this.InternalRecipients.Find(r => r.PublicKey.Equals(recipient.PublicKey));
            if (existingRecipient == default)
            {
                this.InternalRecipients.Add(recipient);
            }
            else
            {
                throw new EncryptedContainerException($"Recipient {recipient.Name} was already added to recipient list.");
            }
        }

        private void RemoveRecipient(PublicKey pk)
        {
            var existingRecipient = this.InternalRecipients.Find(r => r.PublicKey.Equals(pk));
            if (existingRecipient == default)
            {
                throw new EncryptedContainerException($"Given Public Key is no recipient.");
            }
            else
            {
                this.InternalRecipients.Remove(existingRecipient);
            }
        }

        public void Dispose()
        {
            this.ContentStream.Dispose();
        }
    }
}
