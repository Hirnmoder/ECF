using System.Diagnostics;
using System.Runtime.CompilerServices;
using ECF.Core.Container;

namespace ECF.Test
{
    public abstract class EncryptedContainerPerformanceTestBase : EncryptedContainerTest
    {
        public Dictionary<string, List<double>> PerformanceMeasurements = new();
        public int DefaultSamples { get; set; } = 100;

        protected EncryptedContainerPerformanceTestBase(CipherSuite cipherSuite) : base(cipherSuite)
        { }

        protected void AddTime(string action, double seconds, string methodParam = "", [CallerMemberName] string method = "???")
        {
            var key = $"{method}({methodParam})_{action}";
            if (!this.PerformanceMeasurements.ContainsKey(key))
                this.PerformanceMeasurements.Add(key, new());
            this.PerformanceMeasurements[key].Add(seconds);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        protected double TimeIt(string actionName, Action action, string methodParam = "", [CallerMemberName] string method = "???")
        {
            var sw = Stopwatch.StartNew();
            action();
            sw.Stop();
            this.AddTime(actionName, sw.Elapsed.TotalSeconds, methodParam, method);
            return sw.Elapsed.TotalSeconds;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        protected T TimeIt<T>(string actionName, Func<T> action, string methodParam = "", [CallerMemberName] string method = "???")
        {
            var sw = Stopwatch.StartNew();
            T result = action();
            sw.Stop();
            this.AddTime(actionName, sw.Elapsed.TotalSeconds, methodParam, method);
            return result;
        }

        protected double TimeForEach<T>(string actionName, IEnumerable<T> elements, Action<T> action, string methodParam = "", [CallerMemberName] string method = "???")
        {
            var times = new List<double>();
            foreach (var e in elements)
                times.Add(this.TimeIt(actionName, () => action(e), methodParam, method));
            return times.Sum();
        }
    }
}