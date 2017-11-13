using System;

namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class SalsaCore
    {
        public static void HSalsa(out Array16<uint> output, ref Array16<uint> input, int rounds)
        {
            if (rounds % 2 != 0)
                throw new ArgumentException($"{nameof(rounds)} must be even");

            var doubleRounds = rounds / 2;

            unchecked
            {
                for (var i = 0; i < doubleRounds; i++)
                {
                    uint y;

                    // row 0
                    y = input.X0 + input.X12;
                    input.X4 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X4 + input.X0;
                    input.X8 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X8 + input.X4;
                    input.X12 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X12 + input.X8;
                    input.X0 ^= (y << 18) | (y >> (32 - 18));

                    // row 1
                    y = input.X5 + input.X1;
                    input.X9 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X9 + input.X5;
                    input.X13 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X13 + input.X9;
                    input.X1 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X1 + input.X13;
                    input.X5 ^= (y << 18) | (y >> (32 - 18));

                    // row 2
                    y = input.X10 + input.X6;
                    input.X14 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X14 + input.X10;
                    input.X2 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X2 + input.X14;
                    input.X6 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X6 + input.X2;
                    input.X10 ^= (y << 18) | (y >> (32 - 18));

                    // row 3
                    y = input.X15 + input.X11;
                    input.X3 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X3 + input.X15;
                    input.X7 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X7 + input.X3;
                    input.X11 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X11 + input.X7;
                    input.X15 ^= (y << 18) | (y >> (32 - 18));

                    // column 0
                    y = input.X0 + input.X3;
                    input.X1 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X1 + input.X0;
                    input.X2 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X2 + input.X1;
                    input.X3 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X3 + input.X2;
                    input.X0 ^= (y << 18) | (y >> (32 - 18));

                    // column 1
                    y = input.X5 + input.X4;
                    input.X6 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X6 + input.X5;
                    input.X7 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X7 + input.X6;
                    input.X4 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X4 + input.X7;
                    input.X5 ^= (y << 18) | (y >> (32 - 18));

                    // column 2
                    y = input.X10 + input.X9;
                    input.X11 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X11 + input.X10;
                    input.X8 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X8 + input.X11;
                    input.X9 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X9 + input.X8;
                    input.X10 ^= (y << 18) | (y >> (32 - 18));

                    // column 3
                    y = input.X15 + input.X14;
                    input.X12 ^= (y << 7) | (y >> (32 - 7));
                    y = input.X12 + input.X15;
                    input.X13 ^= (y << 9) | (y >> (32 - 9));
                    y = input.X13 + input.X12;
                    input.X14 ^= (y << 13) | (y >> (32 - 13));
                    y = input.X14 + input.X13;
                    input.X15 ^= (y << 18) | (y >> (32 - 18));
                }
            }

            output.X0 = input.X0;
            output.X1 = input.X1;
            output.X2 = input.X2;
            output.X3 = input.X3;
            output.X4 = input.X4;
            output.X5 = input.X5;
            output.X6 = input.X6;
            output.X7 = input.X7;
            output.X8 = input.X8;
            output.X9 = input.X9;
            output.X10 = input.X10;
            output.X11 = input.X11;
            output.X12 = input.X12;
            output.X13 = input.X13;
            output.X14 = input.X14;
            output.X15 = input.X15;
        }
    }
}
