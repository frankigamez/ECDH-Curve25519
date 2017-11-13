using System;
using System.Linq;
using ECDH25519.Algorithm;

namespace ECDH25519.Implementation
{
    public sealed class SharedSecretKey 
    {
        public byte[] KeyValue { get; }
        internal Guid Uid { get; }
     
        
        /// <summary>
        /// Generates the Shared Key for this pair (My Secret Key - Your Public Key)
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="peerPublicKey"></param>
        internal SharedSecretKey(SecretKey secretKey, PublicKey peerPublicKey)
        {
            KeyValue = AlgorithmService.GetSharedSecretKey(
                privateKey: secretKey.KeyValue,
                peerPublicKey: peerPublicKey.KeyValue);
            Uid = Guid.NewGuid();
        }
                
        public override string ToString() => string.Join("", KeyValue.Select(x => (char) x));
    }
}