namespace ECDH25519.Algorithm.Core.Operations
{
    internal static class ScalarOperations
    {
        public static void Clamp(byte[] s, int offset)
        {
            s[offset + 0] &= 248;
            s[offset + 31] &= 127;
            s[offset + 31] |= 64;
        }
    }
}