using System.Linq;
using ECDH25519.Algorithm;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ECDH25519.Tests
{  
    [TestClass]
    public class AlgorithmCurve25519Tests
    { 
        [TestMethod]
        public void GetPublicKeyAlice()
        {
            var calculatedAlicePublicKey = AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.AlicePrivateKey);
            Assert.IsTrue(NaCL_Curve25519TestVectors.AlicePublicKey.SequenceEqual(calculatedAlicePublicKey));
        }

        [TestMethod]
        public void GetPublicKeyBob()
        {
            var calculatedBobPublicKey = AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.BobPrivateKey);
            Assert.IsTrue(NaCL_Curve25519TestVectors.BobPublicKey.SequenceEqual(calculatedBobPublicKey));
        }

        [TestMethod]
        public void GetPublicKeySegments()
        {
            var privateKey = NaCL_Curve25519TestVectors.BobPrivateKey;
            var calculatedBobPublicKey = AlgorithmService.GetPublicKey(privateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.BobPublicKey, calculatedBobPublicKey);
        }

        [TestMethod]
        public void GetSharedKeySegments()
        {
            var bobPublic = NaCL_Curve25519TestVectors.BobPublicKey;
            var alicePrivate = NaCL_Curve25519TestVectors.AlicePrivateKey;
            var calculatedSharedAlice = AlgorithmService.GetSharedSecretKey(bobPublic, alicePrivate);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice);
        }

        [TestMethod]
        public void GetSharedKeyAliceBob()
        {
            var calculatedSharedAlice = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.BobPublicKey, NaCL_Curve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice);
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank0()
        {
            var calculatedSharedAliceFrank = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey0, NaCL_Curve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank()
        {
            var calculatedSharedAliceFrank = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey, NaCL_Curve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }


        [TestMethod]
        public void GetSharedKeyBobAlice()
        {
            var calculatedSharedBob = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.AlicePublicKey, NaCL_Curve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
        }

        [TestMethod]
        public void GetSharedKeyBobFrank()
        {
            var calculatedSharedBobFrank = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey, NaCL_Curve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.BobFrankSharedKey, calculatedSharedBobFrank);
        }

        [TestMethod]
        public void GetSharedKeyBobAlice2()
        {
            var calculatedSharedBob = AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.AlicePublicKey2, NaCL_Curve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(NaCL_Curve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
        }

        public AlgorithmCurve25519Tests()
        {
            //Warmup
            AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.AlicePrivateKey);
            AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.AlicePublicKey, NaCL_Curve25519TestVectors.AlicePrivateKey);
            AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.BobPublicKey, NaCL_Curve25519TestVectors.BobPrivateKey);
        }
    }
}
