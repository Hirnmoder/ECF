using ECF.Core.Container;
using ECF.Core.Container.Keys;
using ECF.Core.Primitives;

namespace ECF.Test
{
    public abstract class EncryptedContainerPerformancePrimitivesTest : EncryptedContainerPerformanceTestBase
    {
        protected EncryptedContainerPerformancePrimitivesTest(CipherSuite cipherSuite) : base(cipherSuite)
        { }

        [TestMethod] public void Encrypt_1MB_5_yes() => Encrypt(1, 5, true, 1000);
        [TestMethod] public void Encrypt_10MB_5_yes() => Encrypt(10, 5, true);
        [TestMethod] public void Encrypt_100MB_5_yes() => Encrypt(100, 5, true, 50);
        [TestMethod] public void Encrypt_1000MB_5_yes() => Encrypt(1000, 5, true, 10);

        [TestMethod] public void Encrypt_1MB_10_yes() => Encrypt(1, 10, true);
        [TestMethod] public void Encrypt_1MB_20_yes() => Encrypt(1, 20, true);
        [TestMethod] public void Encrypt_1MB_50_yes() => Encrypt(1, 50, true);
        [TestMethod] public void Encrypt_1MB_100_yes() => Encrypt(1, 100, true);
        [TestMethod] public void Encrypt_1MB_1000_yes() => Encrypt(1, 1000, true);

        [TestMethod] public void Encrypt_1MB_5_no() => Encrypt(1, 5, false, 1000);
        [TestMethod] public void Encrypt_1MB_10_no() => Encrypt(1, 10, false);
        [TestMethod] public void Encrypt_1MB_20_no() => Encrypt(1, 20, false);
        [TestMethod] public void Encrypt_1MB_50_no() => Encrypt(1, 50, false);
        [TestMethod] public void Encrypt_1MB_100_no() => Encrypt(1, 100, false);
        [TestMethod] public void Encrypt_1MB_1000_no() => Encrypt(1, 1000, false);



        [TestMethod] public void Decrypt_1MB_5_yes_yes() => Decrypt(1, 5, true, true, 1000);
        [TestMethod] public void Decrypt_10MB_5_yes_yes() => Decrypt(10, 5, true, true);
        [TestMethod] public void Decrypt_100MB_5_yes_yes() => Decrypt(100, 5, true, true, 50);
        [TestMethod] public void Decrypt_1000MB_5_yes_yes() => Decrypt(1000, 5, true, true, 10);

        [TestMethod] public void Decrypt_1MB_10_yes_yes() => Decrypt(1, 10, true, true);
        [TestMethod] public void Decrypt_1MB_20_yes_yes() => Decrypt(1, 20, true, true);
        [TestMethod] public void Decrypt_1MB_50_yes_yes() => Decrypt(1, 50, true, true);
        [TestMethod] public void Decrypt_1MB_100_yes_yes() => Decrypt(1, 100, true, true);
        [TestMethod] public void Decrypt_1MB_1000_yes_yes() => Decrypt(1, 1000, true, true);

        [TestMethod] public void Decrypt_1MB_5_yes_no() => Decrypt(1, 5, true, false, 1000);
        [TestMethod] public void Decrypt_1MB_10_yes_no() => Decrypt(1, 10, true, false);
        [TestMethod] public void Decrypt_1MB_20_yes_no() => Decrypt(1, 20, true, false);
        [TestMethod] public void Decrypt_1MB_50_yes_no() => Decrypt(1, 50, true, false);
        [TestMethod] public void Decrypt_1MB_100_yes_no() => Decrypt(1, 100, true, false);
        [TestMethod] public void Decrypt_1MB_1000_yes_no() => Decrypt(1, 1000, true, false);

        [TestMethod] public void Decrypt_1MB_5_no_yes() => Decrypt(1, 5, false, true, 1000);
        [TestMethod] public void Decrypt_1MB_10_no_yes() => Decrypt(1, 10, false, true);
        [TestMethod] public void Decrypt_1MB_20_no_yes() => Decrypt(1, 20, false, true);
        [TestMethod] public void Decrypt_1MB_50_no_yes() => Decrypt(1, 50, false, true);
        [TestMethod] public void Decrypt_1MB_100_no_yes() => Decrypt(1, 100, false, true);
        [TestMethod] public void Decrypt_1MB_1000_no_yes() => Decrypt(1, 1000, false, true);


        public void Encrypt(int dataSizeMb, int nRecipients, bool deception, int nSamples = 0)
        {
            var parameters = $"{dataSizeMb}MB, n={nRecipients}, {deception}";
            nSamples = nSamples != 0 ? nSamples : this.DefaultSamples;

            var randomDataBuffer = new byte[1024 * 1024];

            var recipients = new ECFKey[nRecipients];
            for (int i = 0; i < nRecipients; i++)
                recipients[i] = this.CipherSuite.CreateECFKey();

            for (int i = 0; i < nSamples; i++)
            {
                if (this.TestContext is EncryptedContainerTestContext ectc)
                    ectc.ReportProgress(i + 1, nSamples);
                GC.Collect(); // Force Garbage Collection to reduce memory consumption of previous iteration

                using (var ms = new MemoryStream())
                {
                    using (var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob))
                    {
                        for (int j = 0; j < nRecipients; j++)
                            ec.AddRecipientFromPrivateKey(recipients[j], RecipientName(j));

                        for (int d = 0; d < dataSizeMb; d++)
                        {
                            randomDataBuffer.AsSpan().FillRandom();
                            ec.ContentStream.Write(randomDataBuffer);
                        }

                        this.TimeIt("Encrypt", () => ec.Write(ms, deception), parameters);
                        ec.Dispose();
                    }
                    ms.Flush();
                    ms.Dispose();
                }
                GC.Collect(); // Force Garbage Collection to reduce memory consumption of this iteration
            }


            for (int i = 0; i < nRecipients; i++)
                recipients[i].Dispose();
        }

        public void Decrypt(int dataSizeMb, int nRecipients, bool deception, bool verify, int nSamples = 0)
        {
            var parameters = $"{dataSizeMb}MB, n={nRecipients}, {deception}, {verify}";
            nSamples = nSamples != 0 ? nSamples : this.DefaultSamples;

            var randomDataBuffer = new byte[1024 * 1024];

            var recipients = new ECFKey[nRecipients];
            for (int i = 0; i < nRecipients; i++)
                recipients[i] = this.CipherSuite.CreateECFKey();

            using var ms = new MemoryStream();
            using var ec = EncryptedContainer.Create(this.CipherSuite, ContentType.Blob);
            for (int i = 0; i < nRecipients; i++)
                ec.AddRecipientFromPrivateKey(recipients[i], RecipientName(i));

            for (int d = 0; d < dataSizeMb; d++)
            {
                randomDataBuffer.AsSpan().FillRandom();
                ec.ContentStream.Write(randomDataBuffer);
            }

            for (int i = 0; i < nSamples; i++)
            {
                if (this.TestContext is EncryptedContainerTestContext ectc)
                    ectc.ReportProgress(i + 1, nSamples);
                GC.Collect(); // Force Garbage Collection to reduce memory consumption of previous iteration

                ms.Position = 0;
                ms.SetLength(0);
                ec.Write(ms, deception); // Write a new container each time, since m can get chosen randomly -> maybe affects decryption time
                ms.Position = 0;

                using (var ecd = this.TimeIt("Decrypt", () => EncryptedContainer.Load(ms, recipients[i % nRecipients], verify), parameters))
                {
                    ecd.Dispose();
                }

                GC.Collect(); // Force Garbage Collection to reduce memory consumption of this iteration
            }


            for (int i = 0; i < nRecipients; i++)
                recipients[i].Dispose();
        }
    }
}