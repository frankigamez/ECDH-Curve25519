namespace ECDH25519.Algorithm.Core
{
    internal static class ByteIntegerConverter
    {        
        public static uint LoadLittleEndian32(byte[] buf, int offset)
        {
            return buf[offset + 0]
            | (((uint)(buf[offset + 1])) << 8)
            | (((uint)(buf[offset + 2])) << 16)
            | (((uint)(buf[offset + 3])) << 24);
        }

        public static void StoreLittleEndian32(byte[] buf, int offset, uint value)
        {
            buf[offset + 0] = unchecked((byte)value);
            buf[offset + 1] = unchecked((byte)(value >> 8));
            buf[offset + 2] = unchecked((byte)(value >> 16));
            buf[offset + 3] = unchecked((byte)(value >> 24));
        }
    }
}
