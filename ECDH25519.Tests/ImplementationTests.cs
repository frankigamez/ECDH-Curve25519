using System.Diagnostics;
using System.Linq;
using ECDH25519.Implementation;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ECDH25519.Tests
{
    [TestClass]
    public class ImplementationTests

    {
        [TestMethod]
        public void DiffieHellmanImpl_Success_Test()
        {
            var alicePrivate = new SecretKey();
            var alicePublic = alicePrivate.GetPublicKey();

            var bobPrivate = new SecretKey();
            var bobPublic = bobPrivate.GetPublicKey();

            var aliceShared = alicePrivate.GetSharedSecretKey(peerPublicKey: bobPublic);
            var bobShared = bobPrivate.GetSharedSecretKey(peerPublicKey: alicePublic);

            Assert.AreEqual(aliceShared.ToString(), bobShared.ToString());
            TestHelpers.AssertEqualBytes(aliceShared.KeyValue, bobShared.KeyValue);
        }

        [TestMethod]
        public void DiffieHellmanImpl_Fail_Test()
        {
            var alicePrivate = new SecretKey();
            var alicePublic = alicePrivate.GetPublicKey();

            var bobPrivate = new SecretKey();
            var bobPublic = bobPrivate.GetPublicKey();

            alicePublic.KeyValue = alicePublic.KeyValue.ToggleBitInKey();

            var aliceShared = alicePrivate.GetSharedSecretKey(peerPublicKey: bobPublic);
            var bobShared = bobPrivate.GetSharedSecretKey(peerPublicKey: alicePublic);

            Assert.AreNotEqual(aliceShared.ToString(), bobShared.ToString());
            TestHelpers.AssertNotEqualBytes(aliceShared.KeyValue, bobShared.KeyValue);
        }

        [TestMethod]
        public void DiffieHellmanImpl_Success_Timing()
        {
            const int tries = 1000;
            var stopwatch = new Stopwatch();
            var min = long.MaxValue;
            var max = long.MinValue;
            var sum = 0L;

            for (var i = 0; i < tries; i++)
            {
                stopwatch.Restart();

                DiffieHellmanImpl_Success_Test();

                stopwatch.Stop();
                sum += stopwatch.ElapsedTicks;
                if (stopwatch.ElapsedTicks < min) min = stopwatch.ElapsedTicks;
                if (stopwatch.ElapsedTicks > max) max = stopwatch.ElapsedTicks;
            }

            var med = (double) sum / tries;

            Assert.Inconclusive(
                $"Repeats: {tries}times, Total Time: {sum}ticks, Med:{med}ticks, Min:{min}ticks, Max:{max}ticks");
        }
    }
}