using System;
using System.Linq;
using ECDH25519.Algorithm;

namespace ECDH25519.Implementation
{
    public sealed class SecretKey
    {                
        private readonly byte[] _secretKeyValue;
        public byte[] KeyValue => _secretKeyValue;

        private PublicKey _publicKey;

        public SecretKey()
        {
            _secretKeyValue = AlgorithmService.GetRandomPrivateKey();
        }


        /// <summary>
        /// Obtains the Public Key out this Secret Key
        /// </summary>
        /// <returns>Public Key for this Private Key</returns>
        public PublicKey GetPublicKey() 
            => _publicKey ?? (_publicKey = new PublicKey(secretKey: this));


        /// <summary>
        /// Obtains the Shared Secret Key for the pair My Secret Key <-> Your Public Key
        /// </summary>
        /// <param name="peerPublicKey">your public key</param>
        /// <returns>Shared Key for this pair</returns>
        /// <exception cref="ArgumentNullException">peerPublicKey can not be null</exception>
        /// <exception cref="ArgumentException">peerPublicKey can not be my own public key</exception>
        public SharedSecretKey GetSharedSecretKey(PublicKey peerPublicKey)
        {
            if (peerPublicKey == null)
                throw new ArgumentNullException(nameof(peerPublicKey));

            if (peerPublicKey.Uid == _publicKey.Uid)
                throw new ArgumentException("peerPublicKey can not be my own public key");
            
            return new SharedSecretKey(secretKey: this, peerPublicKey: peerPublicKey);           
        }                   

        public override string ToString() => string.Join("", KeyValue.Select(x => (char) x));
    }
}