using ECF.Core.Container;
using ECF.Core.Primitives;
using System.Diagnostics;
using System.Text;

namespace ECF.Test
{
    public abstract class EncryptedContainerTest
    {
        private CipherSuite CipherSuite { get; }

        protected EncryptedContainerTest(CipherSuite cipherSuite)
        {
            this.CipherSuite = cipherSuite;
        }

        private static string RecipientName(int id) => $"Recipient_{id}";

        public TestContext TestContext { get; set; }

        [TestMethod]
        public void CreateAndDecryptContainer()
        {
            using var key = ECFKey.Create();

            using var ec = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);
            ec.AddRecipientFromPrivateKey(key, RecipientName(0));
            using var ms = new MemoryStream();
            ec.Write(ms);

            ms.Position = 0;
            using var ecd = EncryptedContainer.Load(ms, key);

            Assert.IsNotNull(ecd);
            Assert.AreEqual(1, ecd.Recipients.Length);
        }

        [TestMethod]
        public void CreateAndDecryptContainerWithContent()
        {
            var randomData = new byte[1024 * 1024 * 10]; // 10 MB
            randomData.AsSpan().FillRandom();

            using var key = ECFKey.Create();

            using var ec = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);
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
        public void TimeWritingAndLoading()
        {
            var sw = Stopwatch.StartNew();

            const int n = 1000;
            var streams = new MemoryStream[n];
            for (int i = 0; i < n; i++)
                streams[i] = new MemoryStream(1024);

            using var key = ECFKey.Create();

            using var container = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);
            container.AddRecipientFromPrivateKey(key, RecipientName(0));
            using (var strw = new StreamWriter(container.ContentStream, Encoding.UTF8, leaveOpen: true))
            {
                strw.WriteLine("Writing some dummy data to be encrypted within Encrypted Container");
                strw.WriteLine("Writing some more data");
                strw.WriteLine("And another line of text shall be protected.");
                strw.Flush();
                strw.Close();
            }

            var loadedContainer = new EncryptedContainer[n];

            sw.Stop();
            this.TestContext.WriteLine($"Preparation took {sw.ElapsedMilliseconds}ms");

            // Writing
            sw.Restart();

            for (int i = 0; i < n; i++)
            {
                container.Write(streams[i]);
            }

            sw.Stop();
            this.TestContext.WriteLine($"Writing took {sw.ElapsedMilliseconds}ms for {n} container");

            // Reset for Loading
            for (int i = 0; i < n; i++)
            {
                streams[i].Flush();
                streams[i].Position = 0;
            }


            // Loading
            sw.Restart();

            for (int i = 0; i < n; i++)
            {
                loadedContainer[i] = EncryptedContainer.Load(streams[i], key);
            }

            sw.Stop();
            this.TestContext.WriteLine($"Loading took {sw.ElapsedMilliseconds}ms for {n} container");

            // Disposing at end
            for (int i = 0; i < n; i++)
                streams[i].Dispose();

            // Validation if container were loaded correctly
            for (int i = 0; i < n; i++)
            {
                using (var strr = new StreamReader(loadedContainer[i].ContentStream, Encoding.UTF8, leaveOpen: true))
                {
                    Assert.AreEqual("Writing some dummy data to be encrypted within Encrypted Container", strr.ReadLine());
                    Assert.AreEqual("Writing some more data", strr.ReadLine());
                    Assert.AreEqual("And another line of text shall be protected.", strr.ReadLine());
                }
            }

            // Disposing of containers
            for (int i = 0; i < n; i++)
            {
                loadedContainer[i].Dispose();
            }
        }


        [TestMethod]
        public void TimeWritingAndLoadingSingleStream()
        {
            var sw = Stopwatch.StartNew();

            const int n = 10000;
            var writingTimes = new long[n];
            var loadingTimes = new long[n];

            using var key = ECFKey.Create();

            using var container = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);
            container.AddRecipientFromPrivateKey(key, RecipientName(0));
            using (var strw = new StreamWriter(container.ContentStream, Encoding.UTF8, leaveOpen: true))
            {
                strw.WriteLine("Writing some dummy data to be encrypted within Encrypted Container");
                strw.WriteLine("Writing some more data");
                strw.WriteLine("And another line of text shall be protected.");
                strw.Flush();
                strw.Close();
            }

            sw.Stop();
            this.TestContext.WriteLine($"Preparation took {sw.ElapsedMilliseconds}ms");

            using var stream = new MemoryStream(1024);
            for (int i = 0; i < n; i++)
            {
                // Reset for Writing
                stream.SetLength(0);
                stream.Position = 0;

                // Writing
                sw.Restart();
                container.Write(stream);
                sw.Stop();
                writingTimes[i] = sw.ElapsedTicks;

                // Reset for Loading
                stream.Position = 0;

                // Loading
                sw.Restart();
                using var lc = EncryptedContainer.Load(stream, key);
                sw.Stop();
                loadingTimes[i] = sw.ElapsedTicks;

                using (var strr = new StreamReader(lc.ContentStream, Encoding.UTF8, leaveOpen: true))
                {
                    Assert.AreEqual("Writing some dummy data to be encrypted within Encrypted Container", strr.ReadLine());
                    Assert.AreEqual("Writing some more data", strr.ReadLine());
                    Assert.AreEqual("And another line of text shall be protected.", strr.ReadLine());
                }

            }
            stream.Dispose();

            this.TestContext.WriteLine($"Average loading time: {loadingTimes.Average() / Stopwatch.Frequency * 1000} ms");
            this.TestContext.WriteLine($"Average writing time: {writingTimes.Average() / Stopwatch.Frequency * 1000} ms");
        }


        [TestMethod]
        public void CreateAndDecryptContainerMultipleKeys()
        {
            const int n = 200;
            var keys = new ECFKey[n];
            for (int i = 0; i < n; i++)
                keys[i] = ECFKey.Create();

            var loadingTimes = new long[n];

            using var ec = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < n; i++)
                ec.AddRecipientFromPrivateKey(keys[i], RecipientName(i));
            sw.Stop();
            this.TestContext.WriteLine($"Adding Recipients took {sw.ElapsedMilliseconds}ms");

            ec.ContentStream.Write(Encoding.UTF8.GetBytes(nameof(CreateAndDecryptContainerMultipleKeys)));

            using var ms = new MemoryStream(1024);
            ec.Write(ms);

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;

                sw.Restart();
                using var loadedEc = EncryptedContainer.Load(ms, keys[i], i == 0);
                sw.Stop();
                loadingTimes[i] = sw.ElapsedMilliseconds;

                Assert.AreEqual(n, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            this.TestContext.WriteLine($"Loading times: {loadingTimes.Average()}ms (avg), {loadingTimes.Min()}ms (min), {loadingTimes.Max()}ms (max)");

            for (int i = 0; i < n; i++)
                keys[i].Dispose();
        }

        [TestMethod]
        public void CreateAndDecryptContainerMultipleKeysAddRecipient()
        {
            const int n = 200;

            using var masterKey = ECFKey.Create();

            var keysToAdd = new ECFKey[n];
            for (int i = 0; i < n; i++)
                keysToAdd[i] = ECFKey.Create();

            var loadingTimes = new long[n];

            using var ec = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);

            var sw = Stopwatch.StartNew();
            ec.AddRecipientFromPrivateKey(masterKey, RecipientName(-1));
            for (int i = 0; i < n; i++)
            {
                using var rms = new MemoryStream();
                var r = keysToAdd[i].ExportAsRecipient(ec.CipherSuite, RecipientName(i));
                r.Write(rms);
                rms.Position = 0;
                ec.AddRecipientFromExport(rms);
                rms.Close();
                rms.Dispose();
            }
            sw.Stop();
            this.TestContext.WriteLine($"Adding Recipients took {sw.ElapsedMilliseconds}ms");

            ec.ContentStream.Write(Encoding.UTF8.GetBytes(nameof(CreateAndDecryptContainerMultipleKeysAddRecipient)));

            using var ms = new MemoryStream(1024);
            ec.Write(ms);

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;

                sw.Restart();
                using var loadedEc = EncryptedContainer.Load(ms, keysToAdd[i], i == 0);
                sw.Stop();
                loadingTimes[i] = sw.ElapsedMilliseconds;

                Assert.AreEqual(n + 1, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            this.TestContext.WriteLine($"Loading times: {loadingTimes.Average()}ms (avg), {loadingTimes.Min()}ms (min), {loadingTimes.Max()}ms (max)");

            for (int i = 0; i < n; i++)
                keysToAdd[i].Dispose();
        }

        [TestMethod]
        public void AddAndRemoveRecipient()
        {
            var randomData = new byte[1024 * 1024 * 10]; // 10 MB
            randomData.AsSpan().FillRandom();

            using var key1 = ECFKey.Create();
            using var key2 = ECFKey.Create();
            using var key3 = ECFKey.Create();

            using var ec = EncryptedContainer.Create(CipherSuite.X25519_AESgcm_Ed25519_Sha256, ContentType.Blob);
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


            private void AssertEC(EncryptedContainer expected, EncryptedContainer actual)
        {
            Assert.AreEqual(expected.ContainerVersion, actual.ContainerVersion);
            Assert.AreEqual(expected.ContentType, actual.ContentType);
            Assert.AreEqual(expected.Recipients.Length, actual.Recipients.Length);
            for (int i = 0; i < expected.Recipients.Length; i++)
            {
                Assert.AreEqual(expected.Recipients[i].Name, actual.Recipients[i].Name);
                Assert.IsTrue(expected.Recipients[i].PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey).SequenceEqual(actual.Recipients[i].PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey)));
                Assert.IsTrue(expected.Recipients[i].NameSignature.SequenceEqual(actual.Recipients[i].NameSignature));
            }
            Assert.AreEqual(expected.ContentStream.Length, actual.ContentStream.Length);
            using var msExpected = new MemoryStream();
            using var msActual = new MemoryStream();
            expected.ContentStream.Position = 0;
            actual.ContentStream.Position = 0;

            expected.ContentStream.CopyTo(msExpected);
            actual.ContentStream.CopyTo(msActual);

            Assert.IsTrue(msExpected.ToArray().SequenceEqual(msActual.ToArray()));
        }
    }

    [TestClass]
    public class EncryptedContainerTest_CSX25519AesGcmEd25519Sha256 : EncryptedContainerTest
    {
        public EncryptedContainerTest_CSX25519AesGcmEd25519Sha256()
            : base(CipherSuite.X25519_AESgcm_Ed25519_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerTest_CSX25519AesGcmEd25519Sha512 : EncryptedContainerTest
    {
        public EncryptedContainerTest_CSX25519AesGcmEd25519Sha512()
            : base(CipherSuite.X25519_AESgcm_Ed25519_Sha512)
        {
        }
    }
}
