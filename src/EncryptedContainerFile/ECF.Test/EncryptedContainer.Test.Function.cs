using ECF.Core.Container;
using ECF.Core.Container.Keys;
using ECF.Core.Primitives;

namespace ECF.Test
{
    public abstract class EncryptedContainerFunctionTest : EncryptedContainerTest
    {
        protected EncryptedContainerFunctionTest(CipherSuite cipherSuite) : base(cipherSuite)
        { }

        [TestMethod]
        public void CreateAndDecryptContainer()
        {
            using var key = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(key, RecipientName(0));
            using var ms = new MemoryStream();
            ec.Write(ms);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, key);

            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);
        }

        [TestMethod]
        public void UnicodeRecipientName()
        {
            string name = "hello 👋🏻";

            using var key = this.CipherSuite.CreateECFKey();
            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(key, name);
            using var ms = new MemoryStream();
            ec.Write(ms);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, key, true);

            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);
            Assert.AreEqual(name, ecd.Recipients[0].Name);
        }

        [TestMethod]
        public void AddRecipientTwiceByPublicKey()
        {
            using var kCreator = this.CipherSuite.CreateECFKey();
            using var kRecipient = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(kCreator, RecipientName(0), false);
            using var ms = new MemoryStream();
            ec.Write(ms, true);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, kCreator, true);
            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);

            using var msRecipientA = new MemoryStream();
            kRecipient.ExportAsRecipient(this.CipherSuite, RecipientName(1)).Write(msRecipientA);
            msRecipientA.Position = 0;
            using var msRecipientB = new MemoryStream();
            kRecipient.ExportAsRecipient(this.CipherSuite, RecipientName(2)).Write(msRecipientB);
            msRecipientB.Position = 0;

            ecd.AddRecipientFromExport(msRecipientA, true);
            msRecipientA.Position = 0;
            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ecd.AddRecipientFromExport(msRecipientA, true);
            });
            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ecd.AddRecipientFromExport(msRecipientB, true);
            });
            Assert.AreEqual(2, ecd.Recipients.Length);

            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ecd.AddRecipientFromPrivateKey(kRecipient, RecipientName(2), true);
            });
            Assert.AreEqual(2, ecd.Recipients.Length);

            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ecd.AddRecipientFromPrivateKey(kCreator, RecipientName(2), true);
            });
            Assert.AreEqual(2, ecd.Recipients.Length);

            ms.Position = 0;
            ms.SetLength(0);
            ecd.Write(ms, true);
            ms.Position = 0;

            using var ecdd = EncryptedContainer.Load(ms, kRecipient, true);
            Assert.IsNotNull(ecdd);
            Assert.AreEqual(2, ecdd.Recipients.Length);
        }

        [TestMethod]
        public void AddRecipientTwiceByName()
        {
            using var kCreator = this.CipherSuite.CreateECFKey();
            using var kRecipientA = this.CipherSuite.CreateECFKey();
            using var kRecipientB = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(kCreator, RecipientName(0), false);
            using var ms = new MemoryStream();
            ec.Write(ms, true);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, kCreator, true);
            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);

            using var msRecipientA = new MemoryStream();
            kRecipientA.ExportAsRecipient(this.CipherSuite, RecipientName(1)).Write(msRecipientA);
            msRecipientA.Position = 0;
            using var msRecipientB = new MemoryStream();
            kRecipientB.ExportAsRecipient(this.CipherSuite, RecipientName(1)).Write(msRecipientB);
            msRecipientB.Position = 0;

            ecd.AddRecipientFromExport(msRecipientA, false);
            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ecd.AddRecipientFromExport(msRecipientB, false);
            });
            Assert.AreEqual(2, ecd.Recipients.Length);

            ms.Position = 0;
            ms.SetLength(0);
            ecd.Write(ms, true);
            ms.Position = 0;

            using var ecdd = EncryptedContainer.Load(ms, kRecipientA, true);
            Assert.IsNotNull(ecdd);
            Assert.AreEqual(2, ecdd.Recipients.Length);
        }

        [TestMethod]
        public void AddRecipientTwiceByNameAllow()
        {
            using var kCreator = this.CipherSuite.CreateECFKey();
            using var kRecipientA = this.CipherSuite.CreateECFKey();
            using var kRecipientB = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(kCreator, RecipientName(0), false);
            using var ms = new MemoryStream();
            ec.Write(ms, true);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, kCreator, true);
            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);

            using var msRecipientA = new MemoryStream();
            kRecipientA.ExportAsRecipient(this.CipherSuite, RecipientName(1)).Write(msRecipientA);
            msRecipientA.Position = 0;
            using var msRecipientB = new MemoryStream();
            kRecipientB.ExportAsRecipient(this.CipherSuite, RecipientName(1)).Write(msRecipientB);
            msRecipientB.Position = 0;

            ecd.AddRecipientFromExport(msRecipientA, false);
            ecd.AddRecipientFromExport(msRecipientB, true);
            Assert.AreEqual(3, ecd.Recipients.Length);

            ms.Position = 0;
            ms.SetLength(0);
            ecd.Write(ms, true);
            ms.Position = 0;

            using var ecdd = EncryptedContainer.Load(ms, kRecipientB, true);
            Assert.IsNotNull(ecdd);
            Assert.AreEqual(3, ecdd.Recipients.Length);
        }


        [TestMethod]
        public void AddAndRemoveRecipient()
        {
            var randomData = new byte[1024 * 1024 * 10]; // 10 MB
            randomData.AsSpan().FillRandom();

            using var key1 = this.CipherSuite.CreateECFKey();
            using var key2 = this.CipherSuite.CreateECFKey();
            using var key3 = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(key1, RecipientName(0));

            ec.ContentStream.Write(randomData);

            using var ms = new MemoryStream();
            ec.Write(ms);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, key1);

            AssertLoadedEC(ecd, 1);

            Assert.ThrowsException<EncryptedContainerException>(() =>
            {
                ms.Position = 0;
                using var ecd = EncryptedContainer.Load(ms, key2);
                Assert.Fail(); // This line must not be executed
            });

            ec.AddRecipientFromPrivateKey(key2, RecipientName(1));
            ms.Position = 0;
            ms.SetLength(0);
            ec.Write(ms);
            ms.Position = 0;
            using var ecd2 = EncryptedContainer.Load(ms, key2);
            AssertLoadedEC(ecd2, 2);

            Assert.IsTrue(ec.IsECFKeyRecipient(key1));
            Assert.IsTrue(ec.IsECFKeyRecipient(key2));
            Assert.IsFalse(ec.IsECFKeyRecipient(key3));

            Assert.IsTrue(ecd.IsECFKeyRecipient(key1));
            Assert.IsFalse(ecd.IsECFKeyRecipient(key2));
            Assert.IsFalse(ecd.IsECFKeyRecipient(key3));

            Assert.IsTrue(ecd2.IsECFKeyRecipient(key1));
            Assert.IsTrue(ecd2.IsECFKeyRecipient(key2));
            Assert.IsFalse(ecd2.IsECFKeyRecipient(key3));


            void AssertLoadedEC(EncryptedContainer ec, int recipientLength)
            {
                Assert.IsNotNull(ec);
                Assert.AreEqual(recipientLength, ec.Recipients.Length);
                Assert.AreEqual(randomData.Length, ec.ContentStream.Length);
                using var ms2 = new MemoryStream();
                ec.ContentStream.CopyTo(ms2);
                Assert.IsTrue(randomData.SequenceEqual(ms2.ToArray()));
            }
        }

        [TestMethod]
        public void CreateAndDecryptContainerWithContent10MB()
            => CreateAndDecryptContainerWithContent(10);

        [TestMethod]
        public void CreateAndDecryptContainerWithContent100MB()
            => CreateAndDecryptContainerWithContent(100);

        public void CreateAndDecryptContainerWithContent(int size)
        {
            var randomData = new byte[1024 * 1024 * size]; // size MB
            randomData.AsSpan().FillRandom();

            using var key = this.CipherSuite.CreateECFKey();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(key, RecipientName(0));

            ec.ContentStream.Write(randomData);

            using var ms = new MemoryStream();
            ec.Write(ms);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, key);

            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);
            Assert.AreEqual(randomData.Length, ecd.ContentStream.Length);
            using var ms2 = new MemoryStream();
            ecd.ContentStream.CopyTo(ms2);
            Assert.IsTrue(randomData.SequenceEqual(ms2.ToArray()));
        }

        [TestMethod]
        public void CreateSaveAndLoadECFKey()
        {
            using var passwordBuffer = new FixedBytes(32);
            passwordBuffer.GetDataAsSpan().FillRandom();
            using var password = new FixedMemoryStream(passwordBuffer, false);
            using var key = this.CipherSuite.CreateECFKey();
            using var ms = new MemoryStream();
            key.Save(ms, password, 1, 1, new ECFKeyPBKDFArgon2id.Argon2idConfiguration(1, 1000, 1));
            Assert.IsTrue(ms.Length > 0);
            var pos = ms.Position;
            ms.Position = 0;
            using var key2 = ECFKey.Load(ms, password);
            Assert.AreEqual(pos, ms.Position);

            Assert.IsTrue(key.GetRecipientPublicKey(this.CipherSuite).Equals(key2.GetRecipientPublicKey(this.CipherSuite)));
        }
    }
}
