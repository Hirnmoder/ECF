using System;

namespace ECF.Core.Container
{
    /// <summary>
    /// Represents errors that occur during a <see cref="EncryptedContainer"/> operation.
    /// </summary>
    public class EncryptedContainerException : Exception
    {
        /// <inheritdoc cref="Exception.Exception(string?, Exception?)"/>
        public EncryptedContainerException(string? message, Exception? innerException = null)
            : base(message, innerException)
        {
        }
    }
}
