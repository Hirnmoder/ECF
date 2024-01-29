using System;
using System.Diagnostics;
using System.IO;

namespace ECF.Core.Primitives
{
    public class FixedMemoryStream : Stream
    {
        private long _Length = 0;
        private long _Pos = 0;
        private long _Capacity => this._Buffer.Length;
        private FixedBytes? _Buffer;

        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite { get; }

        public override long Length => this._Length;

        public override long Position
        {
            get => _Pos;
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value));
                if (value > int.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(value));
                this.EnsureCapacity((uint)value);
                this._Pos = value;
            }
        }

        public FixedMemoryStream(uint initialCapacity = 256, bool writeable = true)
        {
            if (initialCapacity <= 0)
                throw new ArgumentOutOfRangeException(nameof(initialCapacity));

            this._Buffer = new FixedBytes(MakePowerOf2(initialCapacity));
            this.CanWrite = writeable;
        }

        internal FixedMemoryStream(FixedBytes buffer, bool writeable = true)
        {
            this._Buffer = buffer;
            this.CanWrite = writeable;
            this._Length = buffer.Length;
        }


        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int countToRead = Math.Min(count, (int)(this.Length - this.Position));
            var source = this._Buffer!.GetDataAsReadOnlySpan().Slice((int)this.Position, countToRead);
            source.CopyTo(buffer.AsSpan()[offset..countToRead]);
            this.Position += countToRead;
            return countToRead;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            this.Position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => this.Position + offset,
                SeekOrigin.End => this.Length - offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            return this.Position;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value));
            if (value > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(value));
            this.EnsureCapacity((uint)value);
            this._Length = value;
            this.Position = Math.Min(this.Position, this.Length);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!this.CanWrite)
                throw new InvalidOperationException("Stream does not allow writing to.");
            this.EnsureCapacity((uint)(this.Position + count));
            this._Buffer!.CopyFrom(buffer.AsSpan()[offset..(offset + count)], (int)this.Position, count);
            this.Position += count;
            this._Length = Math.Max(this.Length, this.Position);
        }

        public ReadOnlySpan<byte> GetAsReadOnlySpan()
            => this._Buffer!.GetDataAsReadOnlySpan()[..(int)this.Length];


        private void EnsureCapacity(uint newCapacity)
        {
            if (this._Capacity < newCapacity)
            {
                var oldBuffer = this._Buffer!;
                var newBuffer = new FixedBytes(MakePowerOf2(newCapacity));
                Debug.Assert(oldBuffer.Length < newBuffer.Length);
                newBuffer.CopyFrom(oldBuffer.GetDataAsReadOnlySpan(), 0);
                this._Buffer = newBuffer;
                oldBuffer.Dispose();
            }
        }

        private static uint MakePowerOf2(uint value)
        {
            uint n = 1;
            while (n < value) n <<= 1;
            return n;
        }


        protected override void Dispose(bool disposing)
        {
            this._Length = 0;
            this._Pos = 0;
            this._Buffer?.Dispose();
            this._Buffer = null;
            base.Dispose(disposing);
        }
    }
}
