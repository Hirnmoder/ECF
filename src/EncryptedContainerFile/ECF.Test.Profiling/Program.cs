using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections;

namespace ECF.Test.Profiling
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var t = new EncryptedContainerTest_CSX25519AesGcmEd25519Sha512();
            t.TestContext = new SimpleTestContext();
            foreach(var m in t.GetType().GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public))
            {
                if(m.GetCustomAttributes(typeof(TestMethodAttribute), false).Length > 0)
                {
                    m.Invoke(t, null);
                }
            }
        }
    }


    internal class SimpleTestContext : TestContext
    {
        public override IDictionary Properties => throw new NotImplementedException();

        public override void AddResultFile(string fileName) => throw new NotImplementedException();
        public override void Write(string message) => Console.Write(message);
        public override void Write(string format, params object[] args) => Console.Write(format, args);
        public override void WriteLine(string message) => Console.WriteLine(message);
        public override void WriteLine(string format, params object[] args) => Console.WriteLine(format, args);
    }
}