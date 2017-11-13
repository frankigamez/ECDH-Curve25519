using System;

namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class Salsa20
    {
        private const uint SalsaConst0 = 0x61707865;
        private const uint SalsaConst1 = 0x3320646e;
        private const uint SalsaConst2 = 0x79622d32;
        private const uint SalsaConst3 = 0x6b206574;
        private static readonly byte[] Zero16 = new byte[16];
        
        public static byte[] HSalsa20(byte[] key)
        {
            var result = new ArraySegment<byte>(key);
            var nonce = new ArraySegment<byte>(Zero16);
            
            var state = new Array16<uint>
            {
                X0 = SalsaConst0,
                X1 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 0),
                X2 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 4),
                X3 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 8),
                X4 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 12),
                X5 = SalsaConst1,
                X6 = ByteIntegerConverter.LoadLittleEndian32(nonce.Array, nonce.Offset + 0),
                X7 = ByteIntegerConverter.LoadLittleEndian32(nonce.Array, nonce.Offset + 4),
                X8 = ByteIntegerConverter.LoadLittleEndian32(nonce.Array, nonce.Offset + 8),
                X9 = ByteIntegerConverter.LoadLittleEndian32(nonce.Array, nonce.Offset + 12),
                X10 = SalsaConst2,
                X11 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 16),
                X12 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 20),
                X13 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 24),
                X14 = ByteIntegerConverter.LoadLittleEndian32(result.Array, result.Offset + 28),
                X15 = SalsaConst3
            };

            SalsaCore.HSalsa(ref state, 20);

            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 0, state.X0);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 4, state.X5);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 8, state.X10);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 12, state.X15);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 16, state.X6);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 20, state.X7);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 24, state.X8);
            ByteIntegerConverter.StoreLittleEndian32(result.Array, result.Offset + 28, state.X9);
            
            return result.Array;
        }
    }
}
