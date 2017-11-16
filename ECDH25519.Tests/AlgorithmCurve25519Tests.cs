using System.Linq;
using ECDH25519.Algorithm;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ECDH25519.Tests
{  
    [TestClass]
    public class AlgorithmCurve25519Tests
    { 
        [TestMethod]
        public void GetPublicKeyAlice() => Assert.IsTrue(NaCL_Curve25519TestVectors.AlicePublicKey
            .SequenceEqual(AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.AlicePrivateKey)));

        [TestMethod]
        public void GetPublicKeyBob() => Assert.IsTrue(NaCL_Curve25519TestVectors.BobPublicKey
            .SequenceEqual(AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.BobPrivateKey)));

        [TestMethod]
        public void GetPublicKeySegments() => Assert.IsTrue(NaCL_Curve25519TestVectors.BobPublicKey
            .SequenceEqual(AlgorithmService.GetPublicKey(NaCL_Curve25519TestVectors.BobPrivateKey)));
        
        [TestMethod]
        public void GetSharedKeyAliceBob() => Assert.IsTrue(NaCL_Curve25519TestVectors.AliceBobSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.BobPublicKey, NaCL_Curve25519TestVectors.AlicePrivateKey)));

        [TestMethod]
        public void GetSharedKeyAliceFrank0() => Assert.IsTrue(NaCL_Curve25519TestVectors.AliceFrankSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey0, NaCL_Curve25519TestVectors.AlicePrivateKey)));

        [TestMethod]
        public void GetSharedKeyAliceFrank() => Assert.IsTrue(NaCL_Curve25519TestVectors.AliceFrankSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey, NaCL_Curve25519TestVectors.AlicePrivateKey)));

        [TestMethod]
        public void GetSharedKeyBobAlice() => Assert.IsTrue(NaCL_Curve25519TestVectors.AliceBobSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.AlicePublicKey, NaCL_Curve25519TestVectors.BobPrivateKey)));

        [TestMethod]
        public void GetSharedKeyBobFrank() => Assert.IsTrue(NaCL_Curve25519TestVectors.BobFrankSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.FrankPublicKey, NaCL_Curve25519TestVectors.BobPrivateKey)));

        [TestMethod]
        public void GetSharedKeyBobAlice2() => Assert.IsTrue(NaCL_Curve25519TestVectors.AliceBobSharedKey
            .SequenceEqual(AlgorithmService.GetSharedSecretKey(NaCL_Curve25519TestVectors.AlicePublicKey2, NaCL_Curve25519TestVectors.BobPrivateKey)));
        
    }
}
