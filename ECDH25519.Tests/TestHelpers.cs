using System;
using System.Collections;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ECDH25519.Tests
{
    internal static class TestHelpers
    {
        public static void AssertEqualBytes(byte[] expected, byte[] actual) 
            => Assert.AreEqual(BitConverter.ToString(expected), BitConverter.ToString(actual));
        
        public static void AssertNotEqualBytes(byte[] notExpected, byte[] actual) 
            => Assert.AreNotEqual(BitConverter.ToString(notExpected), BitConverter.ToString(actual));

        public static byte[] ToggleBitInKey(this byte[] buffer)
        {
            var bitArray = new BitArray(buffer);
            var bitToToggle =  new Random(DateTime.UtcNow.Millisecond).Next(buffer.Length*8);
            var bit = bitArray.Get(bitToToggle);
            bitArray.Set(bitToToggle, !bit);

            var result = new byte[buffer.Length];
            bitArray.CopyTo(result, 0);
            return result;
        }
    }
}