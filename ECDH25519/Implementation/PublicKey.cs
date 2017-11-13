using System;
using System.Linq;
using ECDH25519.Algorithm;

namespace ECDH25519.Implementation
{
    public sealed class PublicKey
    {
        public byte[] KeyValue { get; set; }
        
        internal Guid Uid { get; }
                
        
        /// <summary>
        /// Generates the Public Key for this Private Key
        /// </summary>
        /// <param name="secretKey">My Private Key</param>
        internal PublicKey(SecretKey secretKey)
        {
            KeyValue = AlgorithmService.GetPublicKey(privateKey: secretKey.KeyValue);            
            Uid = Guid.NewGuid();
        }
        
        public override string ToString() => string.Join("", KeyValue.Select(x => (char) x));
    }
}