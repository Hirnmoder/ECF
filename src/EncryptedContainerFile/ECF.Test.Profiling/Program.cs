using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections;

namespace ECF.Test.Profiling
{
    internal class Program
    {
        static void Main(string[] args)
        {
            foreach (var t in new EncryptedContainerPerformanceTest[] {
                new EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha256(),
                new EncryptedContainerPerformanceTest_CSX25519Ed25519AesGcmSha512(),
                new EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha256(),
                new EncryptedContainerPerformanceTest_CSX25519Ed25519AegisSha512(),
            })
            {
                t.TestContext = new SimpleTestContext() { Silent = true };
                var lastLineLength = 0;
                foreach (var m in t.GetType().GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public))
                {
                    if (m.GetCustomAttributes(typeof(TestMethodAttribute), false).Length > 0)
                    {
                        lastLineLength = Write($"Running Test {m.Name}", lastLineLength);
                        m.Invoke(t, null);
                    }
                }
                Write("", lastLineLength);

                Console.WriteLine($"Results for Cipher Suite {t.CipherSuite}");
                foreach (var k in t.PerformanceMeasurements.Keys)
                {
                    var v = t.PerformanceMeasurements[k];
                    Console.WriteLine($"\t{k,65}: {v.Count,6}, {v.Min() * 1000.0,7:f2} <= {v.Average() * 1000.0,7:f2} <= {v.Max() * 1000.0,7:f2} ms, Sum: {v.Sum() * 1000.0,8:f2} ms");
                }
                Console.WriteLine();
                Console.WriteLine();
            }
        }

        static int Write(string message, int lastLineLength)
        {
            for (int i = 0; i < lastLineLength; i++)
                Console.Write("\b");
            for (int i = 0; i < lastLineLength; i++)
                Console.Write(" ");
            for (int i = 0; i < lastLineLength; i++)
                Console.Write("\b");
            Console.Write(message);
            return message.Length;
        }
    }


    internal class SimpleTestContext : TestContext
    {
        public bool Silent { get; set; }


        public override IDictionary Properties => throw new NotImplementedException();

        public override void AddResultFile(string fileName) => throw new NotImplementedException();
        public override void Write(string message) { if (!this.Silent) Console.Write(message); }
        public override void Write(string format, params object[] args) { if (!this.Silent) Console.Write(format, args); }
        public override void WriteLine(string message) { if (!this.Silent) Console.WriteLine(message); }
        public override void WriteLine(string format, params object[] args) { if (!this.Silent) Console.WriteLine(format, args); }
    }
}