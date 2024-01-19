using ECF.Core.Container;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections;
using System.Globalization;
using System.Runtime;
using System.Text;

namespace ECF.Test.Profiling
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"AES-GCM instructions supported by CPU: {NSec.Cryptography.Aes256Gcm.IsSupported}");

            var results = new Dictionary<string, Dictionary<CipherSuite, double[]>>();

            foreach (var t in new EncryptedContainerPerformanceTestBase[] {
                new EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha256(),
                new EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AesGcmSha512(),
                new EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha256(),
                new EncryptedContainerPerformancePrimitivesTest_CSX25519Ed25519AegisSha512(),
            })
            {
                t.TestContext = new SimpleTestContext() { Silent = true, WriteProgressFunc = WriteSub };
                foreach (var m in t.GetType().GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public))
                {
                    if (m.GetCustomAttributes(typeof(TestMethodAttribute), false).Length > 0)
                    {
                        Write($"Running Test {m.Name} ");
                        m.Invoke(t, null);

                        // Force Garbage Collection multiple times to reduce memory consumption of this test run
                        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                        GC.Collect();
                        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
                        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
                    }
                }
                Write("");

                Console.WriteLine($"Results for Cipher Suite {t.CipherSuite}");
                foreach (var k in t.PerformanceMeasurements.Keys)
                {
                    var v = t.PerformanceMeasurements[k];
                    Console.WriteLine($"\t{k,45}: {v.Count,6}, {v.Min() * 1000.0,8:f2} <= {v.Average() * 1000.0,8:f2} <= {v.Max() * 1000.0,8:f2} ms, Sum: {v.Sum() * 1000.0,9:f2} ms");

                    if (!results.ContainsKey(k))
                        results.Add(k, new());
                    if (results[k].ContainsKey(t.CipherSuite))
                        Console.WriteLine($"Result for cipher cuite {t.CipherSuite} and test {k} already present");
                    else
                        results[k].Add(t.CipherSuite, v.ToArray());
                }
                Console.WriteLine();
                Console.WriteLine();
            }

            Write($"Exporting {results.Count} results to CSV ");
            var resultfolder = "./results";
            for (int i = 0; i < results.Keys.Count; i++)
            {
                var k = results.Keys.ElementAt(i);

                var filename = $"{resultfolder}/{k}.csv";
                WriteSub($"{i + 1,2}/{results.Keys.Count}: {filename}");
                Directory.CreateDirectory(resultfolder);
                using var fs = File.Create(filename);
                using var w = new StreamWriter(fs, Encoding.UTF8);

                var v = results[k];
                if (v.Values.Select(data => data.Length).Distinct().Count() != 1)
                    Console.WriteLine($"Inconsistent number of runs for test {k}");

                var ciphersuites = v.Keys.ToList();
                w.Write(string.Join(",", ciphersuites.Select(cs => cs.ToString())));
                w.WriteLine(",run");
                var nSamples = v.Values.First().Length;
                for (int j = 0; j < nSamples; j++)
                {
                    foreach (var cs in ciphersuites)
                    {
                        w.Write(v[cs][j].ToString(CultureInfo.InvariantCulture));
                        w.Write(",");
                    }
                    w.WriteLine(j);
                }
                w.Flush();
            }
            WriteSub("Finished");
            WriteNewLine();
        }

        static int lastLineLength = 0;
        static int lastLineLength2 = 0;
        private static void Write(string message)
        {
            for (int i = 0; i < lastLineLength + lastLineLength2; i++)
                Console.Write("\b");
            if (message.Length < lastLineLength + lastLineLength2)
            {
                for (int i = 0; i < lastLineLength + lastLineLength2; i++)
                    Console.Write(" ");
                for (int i = 0; i < lastLineLength + lastLineLength2; i++)
                    Console.Write("\b");
            }
            Console.Write(message);
            lastLineLength = message.Length;
            lastLineLength2 = 0;
        }

        private static void WriteSub(string message)
        {
            for (int i = 0; i < lastLineLength2; i++)
                Console.Write("\b");
            if (message.Length < lastLineLength2)
            {
                for (int i = 0; i < lastLineLength2; i++)
                    Console.Write(" ");
                for (int i = 0; i < lastLineLength2; i++)
                    Console.Write("\b");
            }
            Console.Write(message);
            lastLineLength2 = message.Length;
        }

        private static void WriteNewLine()
        {
            Console.WriteLine();
            lastLineLength = 0;
            lastLineLength2 = 0;
        }
    }


    internal class SimpleTestContext : EncryptedContainerTestContext
    {
        public bool Silent { get; set; }
        public Action<string> WriteProgressFunc { get; set; }


        public override IDictionary Properties => throw new NotImplementedException();

        public override void AddResultFile(string fileName) => throw new NotImplementedException();
        public override void Write(string message) { if (!this.Silent) Console.Write(message); }
        public override void Write(string format, params object[] args) { if (!this.Silent) Console.Write(format, args); }
        public override void WriteLine(string message) { if (!this.Silent) Console.WriteLine(message); }
        public override void WriteLine(string format, params object[] args) { if (!this.Silent) Console.WriteLine(format, args); }

        public override void ReportProgress(int iteration, int of)
        {
            int digits = of.ToString().Length;
            this.WriteProgressFunc?.Invoke($"{string.Format($"{{0,{digits}}}", iteration)}/{of} ({(double)iteration / of:p1})");
        }
    }
}