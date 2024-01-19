using System.Diagnostics;
using System.Text;
using ECF.Core.Container;
using ECF.Core.Primitives;

namespace ECF.Test
{
    public abstract class EncryptedContainerPerformanceTest : EncryptedContainerPerformanceTestBase
    {
        protected EncryptedContainerPerformanceTest(CipherSuite cipherSuite) : base(cipherSuite)
        { }

        [TestMethod]
        public void WriteAndLoad1k()
            => this.WriteAndLoad(1000);

        [TestMethod]
        public void WriteAndLoad10k()
            => this.WriteAndLoad(10_000);

        public void WriteAndLoad(int n = 1000)
        {
            var sw = Stopwatch.StartNew();

            var streams = new MemoryStream[n];
            for (int i = 0; i < n; i++)
                streams[i] = new MemoryStream(1024);

            using var key = ECFKey.Create();

            using var container = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
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
            this.TestContext.WriteLine($"Preparation took {sw.ElapsedTicks * 1000.0 / Stopwatch.Frequency:n2}ms");
            this.AddTime("Preparation", sw.Elapsed.TotalSeconds, n.ToString());

            // Writing without fake entries
            var total = this.TimeForEach("WriteWithoutDeception", Enumerable.Range(0, n), i =>
            {
                container.Write(streams[i], false);
            }, n.ToString());
            this.TestContext.WriteLine($"Writing took {total * 1000.0:n2}ms for {n} container");

            // Reset for Loading
            for (int i = 0; i < n; i++)
            {
                streams[i].Flush();
                streams[i].Position = 0;
            }

            // Loading without fake entries
            total = this.TimeForEach("LoadWithoutDeception", Enumerable.Range(0, n), i =>
            {
                loadedContainer[i] = EncryptedContainer.Load(streams[i], key, true);
            }, n.ToString());
            this.TestContext.WriteLine($"Loading took {total * 1000.0:n2}ms for {n} container");

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


            // Now do the same with deception blocks
            for (int i = 0; i < n; i++)
                streams[i] = new MemoryStream(1024);

            // Writing with fake entries
            total = this.TimeForEach("WriteWithDeception", Enumerable.Range(0, n), i =>
            {
                container.Write(streams[i], true);
            }, n.ToString());
            this.TestContext.WriteLine($"Writing took {total * 1000.0:n2}ms for {n} container");

            // Reset for Loading
            for (int i = 0; i < n; i++)
            {
                streams[i].Flush();
                streams[i].Position = 0;
            }

            // Loading without fake entries
            total = this.TimeForEach("LoadWithDeception", Enumerable.Range(0, n), i =>
            {
                loadedContainer[i] = EncryptedContainer.Load(streams[i], key, true);
            }, n.ToString());
            this.TestContext.WriteLine($"Loading took {total * 1000.0:n2}ms for {n} container");

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
        public void WriteAndLoadSequentially1k()
            => this.WriteAndLoadSequentially(1000);

        [TestMethod]
        public void WriteAndLoadSequentially10k()
            => this.WriteAndLoadSequentially(10_000);

        public void WriteAndLoadSequentially(int n = 1000)
        {
            var sw = Stopwatch.StartNew();

            using var key = ECFKey.Create();

            using var container = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
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
            this.AddTime("Preparation", sw.Elapsed.TotalSeconds, n.ToString());
            this.TestContext.WriteLine($"Preparation took {sw.Elapsed.TotalMilliseconds:n2}ms");

            using var stream = new MemoryStream(1024);
            for (int i = 0; i < n; i++)
            {
                // Reset for Writing
                stream.SetLength(0);
                stream.Position = 0;

                // Writing
                this.TimeIt("Write", () => container.Write(stream), n.ToString());

                // Reset for Loading
                stream.Position = 0;

                // Loading
                using var lc = this.TimeIt("Load", () => EncryptedContainer.Load(stream, key, true), n.ToString());

                using (var strr = new StreamReader(lc.ContentStream, Encoding.UTF8, leaveOpen: true))
                {
                    Assert.AreEqual("Writing some dummy data to be encrypted within Encrypted Container", strr.ReadLine());
                    Assert.AreEqual("Writing some more data", strr.ReadLine());
                    Assert.AreEqual("And another line of text shall be protected.", strr.ReadLine());
                }

            }
            stream.Dispose();
        }


        [TestMethod]
        public void AddRecipientsAndDecryptByPrivateKey10()
            => AddRecipientsAndDecryptByPrivateKey(10);

        [TestMethod]
        public void AddRecipientsAndDecryptByPrivateKey200()
            => AddRecipientsAndDecryptByPrivateKey(200);

        [TestMethod]
        public void AddRecipientsAndDecryptByPrivateKey500()
            => AddRecipientsAndDecryptByPrivateKey(500);

        [TestMethod]
        public void AddRecipientsAndDecryptByPrivateKey1000()
            => AddRecipientsAndDecryptByPrivateKey(1000);


        public void AddRecipientsAndDecryptByPrivateKey(int n, int nWrites = 100)
        {
            var keys = new ECFKey[n];
            for (int i = 0; i < n; i++)
                keys[i] = ECFKey.Create();

            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);

            this.TimeForEach("AddRecipient", Enumerable.Range(0, n), i =>
            {
                ec.AddRecipientFromPrivateKey(keys[i], RecipientName(i));
            }, n.ToString());

            ec.ContentStream.Write(Encoding.UTF8.GetBytes(nameof(AddRecipientsAndDecryptByPrivateKey)));

            using var ms = new MemoryStream();
            for (int i = 0; i < nWrites; i++)
            {
                ms.Position = 0;
                ms.SetLength(0);
                this.TimeIt("Write", () => ec.Write(ms), n.ToString());
            }

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;

                using var loadedEc = this.TimeIt("LoadWithVerify", () => EncryptedContainer.Load(ms, keys[i], true), n.ToString());
                Assert.AreEqual(n, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;

                using var loadedEc = this.TimeIt("LoadWithoutVerify", () => EncryptedContainer.Load(ms, keys[i], false), n.ToString());
                Assert.AreEqual(n, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            for (int i = 0; i < n; i++)
                keys[i].Dispose();
        }

        [TestMethod]
        public void AddRecipientsAndDecryptByRecipientExport10()
            => AddRecipientsAndDecryptByRecipientExport(10);

        [TestMethod]
        public void AddRecipientsAndDecryptByRecipientExport200()
            => AddRecipientsAndDecryptByRecipientExport(200);

        [TestMethod]
        public void AddRecipientsAndDecryptByRecipientExport500()
            => AddRecipientsAndDecryptByRecipientExport(500);

        [TestMethod]
        public void AddRecipientsAndDecryptByRecipientExport1000()
            => AddRecipientsAndDecryptByRecipientExport(1000);


        public void AddRecipientsAndDecryptByRecipientExport(int n, int nWrites = 100)
        {
            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            using var masterKey = ECFKey.Create();

            var keysToAdd = new ECFKey[n];
            this.TimeForEach("CreateECFKey", Enumerable.Range(0, n), i =>
            {
                keysToAdd[i] = ECFKey.Create();
            }, n.ToString());

            var exportedRecipientStreams = new MemoryStream[n];
            this.TimeForEach("ExportRecipient", Enumerable.Range(0, n), i =>
            {
                exportedRecipientStreams[i] = new MemoryStream();
                keysToAdd[i].ExportAsRecipient(ec.CipherSuite, RecipientName(i)).Write(exportedRecipientStreams[i]);
            }, n.ToString());

            this.TimeIt("AddCreator", () => ec.AddRecipientFromPrivateKey(masterKey, RecipientName(-1)), n.ToString());

            for (int i = 0; i < n; i++)
            {
                using var rms = exportedRecipientStreams[i];
                rms.Position = 0;
                this.TimeIt("AddRecipient", () => ec.AddRecipientFromExport(rms, false), n.ToString());
                rms.Close();
                rms.Dispose();
            }
            ec.ContentStream.Write(Encoding.UTF8.GetBytes(nameof(AddRecipientsAndDecryptByRecipientExport)));

            using var ms = new MemoryStream();
            for (int i = 0; i < nWrites; i++)
            {
                ms.Position = 0;
                ms.SetLength(0);
                this.TimeIt("Write", () => ec.Write(ms), n.ToString());
            }

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;
                using var loadedEc = this.TimeIt("LoadWithVerify", () => EncryptedContainer.Load(ms, keysToAdd[i], true), n.ToString());

                Assert.AreEqual(n + 1, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            for (int i = 0; i < n; i++)
            {
                // Reset memory stream position
                ms.Position = 0;
                using var loadedEc = this.TimeIt("LoadWithoutVerify", () => EncryptedContainer.Load(ms, keysToAdd[i], false), n.ToString());

                Assert.AreEqual(n + 1, loadedEc.Recipients.Length);
                AssertEC(ec, loadedEc);
            }

            for (int i = 0; i < n; i++)
                keysToAdd[i].Dispose();
        }

    }
}