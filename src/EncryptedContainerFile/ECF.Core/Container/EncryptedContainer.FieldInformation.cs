namespace ECF.Core.Container
{
    public partial class EncryptedContainer
    {
        private class FieldLengthInfo
        {
            internal const int VERSION = sizeof(ContainerVersion);
            internal const int CIPHER_SUITE = sizeof(uint);
            internal const int PUBLIC_HEADER_LENGTH = sizeof(int);
            internal const int PRIVATE_LENGTH = sizeof(int);
            internal const int RECIPIENT_COUNT = sizeof(int);
            internal const int RECIPIENT_SALT = 16;
            internal const int RECIPIENT_SALTED_HASH = 16;
            internal const int CONTENT_TYPE = sizeof(uint);
            internal const int CONTENT_LENGTH = sizeof(int);
        }
    }
}
