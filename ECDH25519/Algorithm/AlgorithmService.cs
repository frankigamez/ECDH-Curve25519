using System;
using System.Drawing;
using System.Security.Cryptography;
using ECDH25519.Algorithm.Core.Hash;
using ECDH25519.Algorithm.Core.Operations;

namespace ECDH25519.Algorithm
{
    /// <summary>
    /// This class is mainly for compatibility with NaCl's Curve25519 implementation
    /// </summary>
    public static class AlgorithmService
    {
        private const int SecretKeySizeInBytes = 32;
        private const int PublicKeySizeInBytes = 32;        
        private const int SharedKeySizeInBytes = 32;        
        
        
        
        /// <summary>
        /// Creates a random private key
        /// </summary>
        /// <returns>32 random bytes that are clamped to a suitable private key</returns>
        public static byte[] GetRandomPrivateKey()
        {
            var privateKey = new byte[SecretKeySizeInBytes];
            RandomNumberGenerator.Create().GetBytes(privateKey);
            MontgomeryOperations.Clamp(s: privateKey, offset: 0);           
            return privateKey;
        } 
                       
        
        /// <summary>
        /// Get a Public Key for my Secret Key
        /// </summary>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static byte[] GetPublicKey(byte[] secretKey)
        {
            if (secretKey == null) 
                throw new ArgumentNullException(nameof(secretKey));
            
            if (secretKey.Length != SecretKeySizeInBytes)
                throw new ArgumentException($"{nameof(secretKey)} must be 32");
            
            var publicKey = new byte[32];
            var publicKeySegment = new ArraySegment<byte>(publicKey);
            var secretKeySegment = new ArraySegment<byte>(secretKey);
            
            //Copy PrivateKey to PublicKey (it's not what it seems ... it's to work with a array only)
            for (var i = 0; i < 32; i++)            
                publicKeySegment.Array[publicKeySegment.Offset + i] = secretKeySegment.Array[secretKeySegment.Offset + i];            
            MontgomeryOperations.Clamp(s: publicKeySegment.Array, offset: publicKeySegment.Offset);
                       
            // Edwards to MontgomeryX
            var A = GroupElementsOperations.ScalarmultBase(a: publicKeySegment.Array, offset: publicKeySegment.Offset);
            var tempX = FieldElementOperations.Add(f: ref A.Z, g: ref A.Y);
            var tempZ = FieldElementOperations.Sub(f: ref A.Z, g: ref A.Y);
            tempZ = FieldElementOperations.Invert(z: ref tempZ);
            
            // Obtains the Public Key
            var publicKeyFieldElement = FieldElementOperations.Multiply(f: ref tempX, g: ref tempZ);            
            FieldElementOperations.ToBytes(s: publicKeySegment.Array, offset: publicKeySegment.Offset, h: ref publicKeyFieldElement);
            
            return publicKey;
        }
        
        
        /// <summary>
        /// Get a SharedSecret Key for this pair (my Secret Key - your Public Key)
        /// </summary>
        /// <param name="peerPublicKey"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static byte[] GetSharedSecretKey(byte[] peerPublicKey, byte[] privateKey)
        {
            if (peerPublicKey == null) 
                throw new ArgumentNullException(nameof(peerPublicKey));            
            if (peerPublicKey.Length != PublicKeySizeInBytes)
                throw new ArgumentException($"{nameof(peerPublicKey)} must be 32");
            
            if (privateKey == null) 
                throw new ArgumentNullException(nameof(privateKey));            
            if (privateKey.Length != SecretKeySizeInBytes)
                throw new ArgumentException($"{nameof(privateKey)} must be 32");
            
            //Resolve SharedSecret Key using the Montgomery Elliptical Curve Operations...
            var sharedSecretKey = MontgomeryOperations.ScalarMultiply(n: privateKey, p: peerPublicKey, qSize: SharedKeySizeInBytes);
            
            //hashes like the NaCl paper says instead i.e. HSalsa(x,0)
            sharedSecretKey = Salsa20.HSalsa20(key: sharedSecretKey); 
                     
            return sharedSecretKey;            
        }
    }
}
