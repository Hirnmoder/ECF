using System;
using System.Runtime.InteropServices;

namespace ECF.Core.Primitives
{
    /// <summary>
    /// A memory-fixed array of bytes.
    /// </summary>
    public sealed class FixedBytes : IDisposable
    {
        private readonly byte[] data;
        private readonly GCHandle dataHandle;

        /// <summary>
        /// <inheritdoc cref="Array.Length"/>
        /// </summary>
        public int Length => this.data.Length;

        /// <summary>
        /// Creates a new array that is fixed in memory.
        /// </summary>
        /// <param name="length"></param>
        public FixedBytes(uint length)
        {
            this.data = new byte[length];
            this.dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        }

        /// <summary>
        /// Access to the internal array.
        /// </summary>
        public byte this[int index]
        {
            get => this.data[index];
            set => this.data[index] = value;
        }

        /// <summary>
        /// <inheritdoc cref="IDisposable.Dispose"/>
        /// </summary>
        public void Dispose()
        {
            if (this.data != null)
            {
                for (int i = 0; i < this.data.Length; i++)
                    this.data[i] = default;
            }

            if (this.dataHandle.IsAllocated)
            {
                this.dataHandle.Free();
            }
        }

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        ~FixedBytes()
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        {
            this.Dispose();
        }

        /// <summary>
        /// Returns a <see cref="ReadOnlySpan{Byte}"/> to access the internal bytes.
        /// </summary>
        public ReadOnlySpan<byte> GetDataAsReadOnlySpan()
            => this.GetDataAsSpan();

        /// <summary>
        /// Returns a <see cref="Span{Byte}"/> to access the internal bytes.
        /// </summary>
        /// <returns></returns>
        public Span<byte> GetDataAsSpan()
            => this.data.AsSpan();


        internal void CopyFrom(ReadOnlySpan<byte> source, int destinationStartIndex, int len = int.MaxValue)
        {
            len = Math.Min(len, Math.Min(source.Length, this.Length - destinationStartIndex));

            source[..len].CopyTo(this.data.AsSpan().Slice(destinationStartIndex, len));
        }
    }
}
