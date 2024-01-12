using System;
using System.Collections.Generic;

namespace ECF.Core.Container
{
    public abstract class ContentType
    {
        public static readonly CTBlob Blob = new();

        private static readonly List<ContentType> contentTypes = new();

        public abstract uint Identifier { get; }
        public abstract string FriendlyName { get; }


        static ContentType()
        {
            RegisterContentType(Blob);
        }

        public static void RegisterContentType(ContentType contentType)
        {
            if (contentTypes.Find(ct => ct.Identifier == contentType.Identifier) == default)
            {
                contentTypes.Add(contentType);
            }
            else
            {
                throw new InvalidOperationException($"ContentType with identifier {contentType.Identifier} already exists.");
            }
        }

        public static ContentType GetContentType(uint identifier)
        {
            var ct = contentTypes.Find(ct => ct.Identifier == identifier);
            return ct ?? throw new EncryptedContainerException($"ContentType with identifier {identifier} not found!");
        }
    }

    public class CTBlob : ContentType
    {
        public override uint Identifier => 0x00000001u;
        public override string FriendlyName => "Binary Large Object (BLOB)";
    }


}
