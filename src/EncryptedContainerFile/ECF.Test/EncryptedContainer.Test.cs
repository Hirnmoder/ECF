using ECF.Core.Container;
using ECF.Core.Container.Recipients;

namespace ECF.Test
{
    public abstract class EncryptedContainerTest
    {
        public CipherSuite CipherSuite { get; }

        protected EncryptedContainerTest(CipherSuite cipherSuite)
        {
            this.CipherSuite = cipherSuite;
        }

        protected static string RecipientName(int id) => $"Recipient_{id}";

        public TestContext TestContext { get; set; }

        protected void AssertEC(EncryptedContainer expected, EncryptedContainer actual)
        {
            Assert.AreEqual(expected.ContainerVersion, actual.ContainerVersion);
            Assert.AreEqual(expected.ContentType, actual.ContentType);
            Assert.AreEqual(expected.Recipients.Length, actual.Recipients.Length);
            for (int i = 0; i < expected.Recipients.Length; i++)
            {
                Assert.AreEqual(expected.Recipients[i].Name, actual.Recipients[i].Name);
                if (expected.Recipients[i] is RX25519Ed25519 er && actual.Recipients[i] is RX25519Ed25519 ar)
                {
                    Assert.IsTrue(er.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey).SequenceEqual(ar.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey)));
                }
                else
                    Assert.Fail($"Expected {nameof(RX25519Ed25519)}, got {expected.Recipients[i].GetType().Name}.");
                Assert.IsTrue(expected.Recipients[i].Signature.SequenceEqual(actual.Recipients[i].Signature));
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
    public class EncryptedContainerFunctionTest_CSX25519Ed25519AesGcmSha256 : EncryptedContainerFunctionTest
    {
        public EncryptedContainerFunctionTest_CSX25519Ed25519AesGcmSha256()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerFunctionTest_CSX25519Ed25519AesGcmSha512 : EncryptedContainerFunctionTest
    {
        public EncryptedContainerFunctionTest_CSX25519Ed25519AesGcmSha512()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha512)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerFunctionTest_CSX25519Ed25519AegisSha256 : EncryptedContainerFunctionTest
    {
        public EncryptedContainerFunctionTest_CSX25519Ed25519AegisSha256()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerFunctionTest_CSX25519Ed25519AegisSha512 : EncryptedContainerFunctionTest
    {
        public EncryptedContainerFunctionTest_CSX25519Ed25519AegisSha512()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha512)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha256 : EncryptedContainerPerformanceTest
    {
        public EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha256()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha512 : EncryptedContainerPerformanceTest
    {
        public EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha512()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha512)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha256 : EncryptedContainerPerformanceTest
    {
        public EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha256()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha512 : EncryptedContainerPerformanceTest
    {
        public EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha512()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha512)
        {
        }
    }


    [TestClass]
    public class EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha256 : EncryptedContainerPerformancePrimitivesTest
    {
        public EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha256()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha512 : EncryptedContainerPerformancePrimitivesTest
    {
        public EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha512()
            : base(CipherSuite.X25519_Ed25519_AesGcm_Sha512)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha256 : EncryptedContainerPerformancePrimitivesTest
    {
        public EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha256()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha256)
        {
        }
    }

    [TestClass]
    public class EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha512 : EncryptedContainerPerformancePrimitivesTest
    {
        public EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha512()
            : base(CipherSuite.X25519_Ed25519_Aegis_Sha512)
        {
        }
    }
}