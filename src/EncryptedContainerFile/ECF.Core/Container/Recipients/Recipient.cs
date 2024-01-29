using NSec.Cryptography;
using System.Diagnostics;
using System.IO;

namespace ECF.Core.Container.Recipients
{
    /// <summary>
    /// A recipient of an encrypted container.
    /// </summary>
    public abstract class Recipient
    {
        /// <summary>
        /// A human-readable name/identifier for the recipient.
        /// </summary>
        public virtual string Name { get; }

        /// <summary>
        /// The signature of the name.
        /// </summary>
        protected internal virtual byte[] Signature { get; }


        /// <summary>
        /// Initializes a new instance of the <see cref="Recipient"/> class.
        /// </summary>
        /// <param name="name">A human-readable name/identifier for the recipient.</param>
        /// <param name="signature">The signature of this recipient.</param>
        protected Recipient(string name, byte[] signature)
        {
            Debug.Assert(signature != null, "Signature must not be null.");
            Debug.Assert(name != null, "Name must not be null.");
            Debug.Assert(signature.Length > 0, "Signature must not be empty.");
            Debug.Assert(name.Length > 0, "Name must not be empty.");
            this.Name = name;
            this.Signature = signature;
        }

        /// <summary>
        /// Gets a public key representation of this <see cref="Recipient"/> as a hex string.
        /// </summary>
        /// <returns>A hex string representing the public key of this <see cref="Recipient"/>.</returns>
        public abstract string GetPublicKeyHex();

        /// <summary>
        /// Serializes a <see cref="Recipient"/> object into a stream.
        /// </summary>
        /// <param name="outStream">The <see cref="Stream"/> to write to.</param>
        /// <exception cref="EncryptedContainerException"></exception>
        public abstract void Write(Stream outStream);

        /// <summary>
        /// Compares the public key of this <see cref="Recipient"/> with the given <see cref="PublicKey"/>.
        /// </summary>
        /// <param name="publicKey">The public key to compare against.</param>
        /// <returns>True, if the public keys match; otherwise false.</returns>
        public abstract bool ComparePublicKey(PublicKey publicKey);

        /// <summary>
        /// Compares the public key of this <see cref="Recipient"/> with the public key of the given <see cref="Recipient"/>.
        /// </summary>
        /// <param name="other">The recipient to compare against.</param>
        /// <returns>True, if the public keys match; otherwise false.</returns>
        public abstract bool ComparePublicKey(Recipient other);
    }

    /// <summary>
    /// A recipient of an encrypted container.
    /// </summary>
    public interface IRecipient
    {
        /// <summary>
        /// Loads a <see cref="Recipient"/> object from a stream.
        /// </summary>
        /// <param name="br">The <see cref="BinaryReader"/> to load from.</param>
        /// <param name="cipherSuite">The chosen cipher suite.</param>
        /// <param name="verifySignature">Determines, whether the signature of the loaded <see cref="Recipient"/> should be verified.</param>
        /// <returns>The loaded <see cref="Recipient"/>.</returns>
        static abstract Recipient Load(BinaryReader br, CipherSuite cipherSuite, bool verifySignature);
    }
}
