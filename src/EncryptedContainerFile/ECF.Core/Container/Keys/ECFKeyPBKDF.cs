using System;
using System.IO;
using System.Text;
using ECF.Core.Primitives;
using NSec.Cryptography;

namespace ECF.Core.Container.Keys
{
    /// <summary>
    /// Represents a password-based key derivation function.
    /// </summary>
    public abstract class ECFKeyPBKDF
    {
        /// <summary>
        /// A configuration class for an <see cref="ECFKeyPBKDF"/> object.
        /// </summary>
        public abstract class Configuration { }

        /// <summary>
        /// The length of the salt value.
        /// </summary>
        public virtual int SaltLength => 16;

        /// <summary>
        /// Creates a new <see cref="ECFKeyPBKDF"/> object.
        /// </summary>
        protected ECFKeyPBKDF()
        {
            if (this.SaltLength <= 0)
                throw new InvalidOperationException("Salt length must be greater than 0!");
        }

        /// <summary>
        /// Writes the configuration to the specified stream.
        /// </summary>
        /// <param name="stream">The stream to write the configuration to.</param>
        /// <param name="configuration">The configuration to write.</param>
        public abstract void WriteConfiguration(Stream stream, Configuration configuration);

        /// <summary>
        /// Reads the configuration from the specified stream.
        /// </summary>
        /// <param name="stream">The stream to read the configuration from.</param>
        /// <returns>The read configuration.</returns>
        public abstract Configuration ReadConfiguration(Stream stream);

        /// <summary>
        /// Derives a key from the specified password and salt using the specified configuration.
        /// </summary>
        /// <param name="configuration">The configuration used for key derivation.</param>
        /// <param name="password">The password to derive the key from.</param>
        /// <param name="salt">The salt value used in key derivation.</param>
        /// <param name="algorithm">The algorithm to use the derived key.</param>
        /// <returns>The derived key.</returns>
        public abstract Key DeriveKey(Configuration configuration, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Algorithm algorithm);
    }

    /// <summary>
    /// Represents a password-based key derivation function using Argon2id.
    /// </summary>
    public sealed class ECFKeyPBKDFArgon2id : ECFKeyPBKDF
    {
        /// <summary>
        /// A configuration class for an <see cref="ECFKeyPBKDFArgon2id"/> object.
        /// </summary>
        public sealed class Argon2idConfiguration : Configuration
        {
            /// <summary>
            /// The number of iterations to use.
            /// </summary>
            public uint Iterations { get; set; }

            /// <summary>
            /// The amount of memory to use in KiB.
            /// </summary>
            public uint MemorySize { get; set; }

            /// <summary>
            /// The degree of parallelism to use.
            /// </summary>
            public uint Parallelism { get; set; }

            /// <summary>
            /// Creates a new <see cref="Argon2idConfiguration"/> object based on the specified <see cref="Argon2Parameters"/> object.
            /// </summary>
            /// <param name="argon2Parameters">A Argon2Parameters object.</param>
            /// <exception cref="InvalidDataException"></exception>
            public Argon2idConfiguration(Argon2Parameters argon2Parameters)
                : this((uint)argon2Parameters.NumberOfPasses, (uint)argon2Parameters.MemorySize, (uint)argon2Parameters.DegreeOfParallelism)
            {
            }

            /// <summary>
            /// Creates a new <see cref="Argon2idConfiguration"/> object.
            /// </summary>
            /// <param name="iterations">Number of passes/iterations.</param>
            /// <param name="memorySize">Amount of memory in KiB.</param>
            /// <param name="parallelism">Degree of parallelism.</param>
            /// <exception cref="InvalidDataException"></exception>
            public Argon2idConfiguration(uint iterations, uint memorySize, uint parallelism)
            {
                if (iterations == 0 || memorySize == 0 || parallelism == 0 || parallelism >= (2 << 24))
                    throw new InvalidDataException("Invalid Argon2id configuration!");
                if (parallelism != 1) // Other values are not supported by libsodium
                    throw new InvalidDataException("Parallelism must be 1 for Argon2id!");
                this.Iterations = iterations;
                this.MemorySize = memorySize;
                this.Parallelism = parallelism;
            }
        }


        /// <summary>
        /// The singleton instance of <see cref="ECFKeyPBKDFArgon2id"/>.
        /// </summary>
        public static readonly ECFKeyPBKDFArgon2id Instance = new();
        private ECFKeyPBKDFArgon2id() { }

        /// <inheritdoc/>
        public override Key DeriveKey(Configuration configuration, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Algorithm algorithm)
        {
            if (configuration is not Argon2idConfiguration argon2idConfiguration)
                throw new ArgumentException($"Configuration must be of type {nameof(Argon2idConfiguration)}!");

            var argon2id = PasswordBasedKeyDerivationAlgorithm.Argon2id(new()
            {
                DegreeOfParallelism = (int)argon2idConfiguration.Parallelism,
                NumberOfPasses = (int)argon2idConfiguration.Iterations,
                MemorySize = (int)argon2idConfiguration.MemorySize,
            });
            return argon2id.DeriveKey(password, salt, algorithm);
        }

        /// <inheritdoc/>
        public override Configuration ReadConfiguration(Stream stream)
        {
            using var br = new BinaryReader(stream, Encoding.UTF8, true);
            var it = br.ReadUInt32();
            var ms = br.ReadUInt32();
            var pa = br.ReadUInt32();

            return new Argon2idConfiguration(it, ms, pa);
        }

        /// <inheritdoc/>
        public override void WriteConfiguration(Stream stream, Configuration configuration)
        {
            using var br = new BinaryWriter(stream, Encoding.UTF8, true);
            if (configuration is not Argon2idConfiguration argon2idConfiguration)
                throw new ArgumentException($"Configuration must be of type {nameof(Argon2idConfiguration)}!");

            br.Write(argon2idConfiguration.Iterations);
            br.Write(argon2idConfiguration.MemorySize);
            br.Write(argon2idConfiguration.Parallelism);
        }
    }
}