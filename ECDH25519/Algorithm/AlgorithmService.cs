using System;
using System.Security.Cryptography;
using ECDH25519.Algorithm.Core;
using ECDH25519.Algorithm.Core.Hash;
using ECDH25519.Algorithm.Core.Operations;

namespace ECDH25519.Algorithm
{
    /// <summary>
    /// This class is mainly for compatibility with NaCl's Curve25519 implementation
    /// </summary>
    public static class AlgorithmService
    {
        private const int PublicKeySizeInBytes = 32;
        private const int PrivateKeySizeInBytes = 32;
        private const int SharedKeySizeInBytes = 32;        
        private static readonly byte[] Zero16 = new byte[16];
        
        
        #region PublicKey                
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            if (privateKey == null) 
                throw new ArgumentNullException(nameof(privateKey));
            
            if (privateKey.Length != PrivateKeySizeInBytes)
                throw new ArgumentException($"{nameof(privateKey)} must be 32");
            
            var publicKey = new byte[32];
            ObtainsPublicKey(new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return publicKey;
        }

        private static void ObtainsPublicKey(ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            for (var i = 0; i < 32; i++)            
                publicKey.Array[publicKey.Offset + i] = privateKey.Array[privateKey.Offset + i];
            
            ScalarOperations.Clamp(publicKey.Array, publicKey.Offset);

            var A = GroupElementsOperations.ScalarmultBase(publicKey.Array, publicKey.Offset);
            var publicKeyFE = EdwardsToMontgomeryX(ref A.Y, ref A.Z);
            FieldElementOperations.ToBytes(publicKey.Array, publicKey.Offset, ref publicKeyFE);
        }
        
        private static FieldElement EdwardsToMontgomeryX(ref FieldElement edwardsY, ref FieldElement edwardsZ)
        {
            var tempX = FieldElementOperations.Add(ref edwardsZ, ref edwardsY);
            var tempZ = FieldElementOperations.Sub(ref edwardsZ, ref edwardsY);
            tempZ = FieldElementOperations.Invert(ref tempZ);
            return FieldElementOperations.Multiply(ref tempX, ref tempZ);
        }
        #endregion

        
        #region SharedSecretKey
        public static byte[] GetSharedSecretKey(byte[] peerPublicKey, byte[] privateKey)
        {
            if (peerPublicKey == null) 
                throw new ArgumentNullException(nameof(peerPublicKey));            
            if (peerPublicKey.Length != PublicKeySizeInBytes)
                throw new ArgumentException($"{nameof(peerPublicKey)} must be 32");
            
            if (privateKey == null) 
                throw new ArgumentNullException(nameof(privateKey));            
            if (privateKey.Length != PrivateKeySizeInBytes)
                throw new ArgumentException($"{nameof(privateKey)} must be 32");
            
            var sharedKey = new byte[SharedKeySizeInBytes];
            ObtainsSharedSecretKey(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(peerPublicKey), new ArraySegment<byte>(privateKey));
            return sharedKey;
        }

        private static void ObtainsSharedSecretKey(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {          
            MontgomeryOperations.ScalarMultiply(sharedKey.Array, sharedKey.Offset, privateKey.Array, privateKey.Offset, publicKey.Array, publicKey.Offset);
            KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
        }
        
        /// <summary>
        /// hashes like the NaCl paper says instead i.e. HSalsa(x,0) 
        /// </summary>
        /// <param name="sharedKey"></param>
        /// <param name="offset"></param>
        private static void KeyExchangeOutputHashNaCl(byte[] sharedKey, int offset) 
            => Salsa20.HSalsa20(sharedKey, offset, sharedKey, offset, Zero16, 0);       
        #endregion


        #region SecretKey
        /// <summary>
        /// Creates a random private key
        /// </summary>
        /// <returns>32 random bytes that are clamped to a suitable private key</returns>
        public static byte[] GetRandomPrivateKey()
        {
            var privateKey = new byte[PrivateKeySizeInBytes];
            RandomNumberGenerator.Create().GetBytes(privateKey);
            ScalarOperations.Clamp(privateKey, 0);           
            return privateKey;
        }
        #endregion        
    }
}
