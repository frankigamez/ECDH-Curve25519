using System;

namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class SalsaCore
    {
        public static void HSalsa(ref Array16<uint> state, int rounds)
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
                    y = state.X0 + state.X12;
                    state.X4 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X4 + state.X0;
                    state.X8 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X8 + state.X4;
                    state.X12 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X12 + state.X8;
                    state.X0 ^= (y << 18) | (y >> (32 - 18));

                    // row 1
                    y = state.X5 + state.X1;
                    state.X9 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X9 + state.X5;
                    state.X13 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X13 + state.X9;
                    state.X1 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X1 + state.X13;
                    state.X5 ^= (y << 18) | (y >> (32 - 18));

                    // row 2
                    y = state.X10 + state.X6;
                    state.X14 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X14 + state.X10;
                    state.X2 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X2 + state.X14;
                    state.X6 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X6 + state.X2;
                    state.X10 ^= (y << 18) | (y >> (32 - 18));

                    // row 3
                    y = state.X15 + state.X11;
                    state.X3 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X3 + state.X15;
                    state.X7 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X7 + state.X3;
                    state.X11 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X11 + state.X7;
                    state.X15 ^= (y << 18) | (y >> (32 - 18));

                    // column 0
                    y = state.X0 + state.X3;
                    state.X1 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X1 + state.X0;
                    state.X2 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X2 + state.X1;
                    state.X3 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X3 + state.X2;
                    state.X0 ^= (y << 18) | (y >> (32 - 18));

                    // column 1
                    y = state.X5 + state.X4;
                    state.X6 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X6 + state.X5;
                    state.X7 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X7 + state.X6;
                    state.X4 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X4 + state.X7;
                    state.X5 ^= (y << 18) | (y >> (32 - 18));

                    // column 2
                    y = state.X10 + state.X9;
                    state.X11 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X11 + state.X10;
                    state.X8 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X8 + state.X11;
                    state.X9 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X9 + state.X8;
                    state.X10 ^= (y << 18) | (y >> (32 - 18));

                    // column 3
                    y = state.X15 + state.X14;
                    state.X12 ^= (y << 7) | (y >> (32 - 7));
                    y = state.X12 + state.X15;
                    state.X13 ^= (y << 9) | (y >> (32 - 9));
                    y = state.X13 + state.X12;
                    state.X14 ^= (y << 13) | (y >> (32 - 13));
                    y = state.X14 + state.X13;
                    state.X15 ^= (y << 18) | (y >> (32 - 18));
                }
            }
        }
    }
}
