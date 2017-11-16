using System;

namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class Salsa20
    {
        internal static byte[] HSalsa20(byte[] key)
        {
            var result = CopyFrom(key);

            var state = LoadLittleEndian(result);
            SalsaCore.Salsa20(ref state, 10);
            StoreLittleEndian(result, ref state);
            
            return result;
        }

        private const uint SalsaConst0 = 0x61707865;
        private const uint SalsaConst1 = 0x3320646e;
        private const uint SalsaConst2 = 0x79622d32;
        private const uint SalsaConst3 = 0x6b206574;
        private static readonly byte[] Zero16 = new byte[16];
        private static Array16<uint> LoadLittleEndian(byte[] result)
        {
            var nonce = CopyFrom(Zero16);                                    
            return new Array16<uint>
            {
                X0 = SalsaConst0,
                X1 = LoadLittleEndian32(result, 0),
                X2 = LoadLittleEndian32(result, 4),
                X3 = LoadLittleEndian32(result, 8),
                X4 = LoadLittleEndian32(result, 12),
                X5 = SalsaConst1,
                X6 = LoadLittleEndian32(nonce, 0),
                X7 = LoadLittleEndian32(nonce, 4),
                X8 = LoadLittleEndian32(nonce, 8),
                X9 = LoadLittleEndian32(nonce, 12),
                X10 = SalsaConst2,
                X11 = LoadLittleEndian32(result, 16),
                X12 = LoadLittleEndian32(result, 20),
                X13 = LoadLittleEndian32(result, 24),
                X14 = LoadLittleEndian32(result, 28),
                X15 = SalsaConst3
            };
        }

        private static uint LoadLittleEndian32(byte[] buf, int offset = 0)
            => buf[offset + 0]
               | ((uint) buf[offset + 1] << 8)
               | ((uint) buf[offset + 2] << 16)
               | ((uint) buf[offset + 3] << 24);

        private static void StoreLittleEndian(byte[] result, ref Array16<uint> state)
        {            
            StoreLittleEndian32(result, state.X0, 0);
            StoreLittleEndian32(result, state.X5, 4);
            StoreLittleEndian32(result, state.X10, 8);
            StoreLittleEndian32(result, state.X15, 12);
            StoreLittleEndian32(result, state.X6, 16);
            StoreLittleEndian32(result, state.X7, 20);
            StoreLittleEndian32(result, state.X8, 24);
            StoreLittleEndian32(result, state.X9, 28);
        }
        
        private static void StoreLittleEndian32(byte[] buf, uint value, int offset= 0)
        {
            buf[offset + 0] = unchecked((byte)value);
            buf[offset + 1] = unchecked((byte)(value >> 8));
            buf[offset + 2] = unchecked((byte)(value >> 16));
            buf[offset + 3] = unchecked((byte)(value >> 24));
        }

        private static byte[] CopyFrom(byte[] source)
        {
            var destination = new byte[source.Length];
            Array.Copy(sourceArray: source, destinationArray: destination, length: source.Length);
            return destination;
        }
    }
}
