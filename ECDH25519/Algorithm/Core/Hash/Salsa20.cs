namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class Salsa20
    {
        private const uint SalsaConst0 = 0x61707865;
        private const uint SalsaConst1 = 0x3320646e;
        private const uint SalsaConst2 = 0x79622d32;
        private const uint SalsaConst3 = 0x6b206574;

        public static void HSalsa20(byte[] output, int outputOffset, byte[] key, int keyOffset, byte[] nonce, int nonceOffset)
        {
            Array16<uint> state;
            state.X0 = SalsaConst0;
            state.X1 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 0);
            state.X2 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 4);
            state.X3 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 8);
            state.X4 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 12);
            state.X5 = SalsaConst1;
            state.X6 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 0);
            state.X7 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 4);
            state.X8 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 8);
            state.X9 = ByteIntegerConverter.LoadLittleEndian32(nonce, nonceOffset + 12);
            state.X10 = SalsaConst2;
            state.X11 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 16);
            state.X12 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 20);
            state.X13 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 24);
            state.X14 = ByteIntegerConverter.LoadLittleEndian32(key, keyOffset + 28);
            state.X15 = SalsaConst3;

            SalsaCore.HSalsa(out state, ref state, 20);

            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 0, state.X0);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 4, state.X5);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 8, state.X10);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 12, state.X15);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 16, state.X6);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 20, state.X7);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 24, state.X8);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 28, state.X9);
        }
    }
}
