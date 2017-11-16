namespace ECDH25519.Algorithm.Core.Hash
{
    internal static class SalsaCore
    {
        internal static void Salsa20(ref Array16<uint> state, int doubleRounds)
        {            
            unchecked
            {
                for (var i = 0; i < doubleRounds; i++)
                {
                    #region RowRound
                    // row 0
                    state.X4 ^= (state.X0 + state.X12 << 7) | (state.X0 + state.X12 >> (32 - 7));
                    state.X8 ^= (state.X4 + state.X0 << 9) | (state.X4 + state.X0 >> (32 - 9));
                    state.X12 ^= (state.X8 + state.X4 << 13) | (state.X8 + state.X4 >> (32 - 13));
                    state.X0 ^= (state.X12 + state.X8 << 18) | (state.X12 + state.X8 >> (32 - 18));

                    // row 1
                    state.X9 ^= (state.X5 + state.X1 << 7) | (state.X5 + state.X1 >> (32 - 7));
                    state.X13 ^= (state.X9 + state.X5 << 9) | (state.X9 + state.X5 >> (32 - 9));
                    state.X1 ^= (state.X13 + state.X9 << 13) | (state.X13 + state.X9 >> (32 - 13));
                    state.X5 ^= (state.X1 + state.X13 << 18) | (state.X1 + state.X13 >> (32 - 18));

                    // row 2
                    state.X14 ^= (state.X10 + state.X6 << 7) | (state.X10 + state.X6 >> (32 - 7));
                    state.X2 ^= (state.X14 + state.X10 << 9) | (state.X14 + state.X10 >> (32 - 9));
                    state.X6 ^= (state.X2 + state.X14 << 13) | (state.X2 + state.X14 >> (32 - 13));
                    state.X10 ^= (state.X6 + state.X2 << 18) | (state.X6 + state.X2 >> (32 - 18));

                    // row 3
                    state.X3 ^= (state.X15 + state.X11 << 7) | (state.X15 + state.X11 >> (32 - 7));
                    state.X7 ^= (state.X3 + state.X15 << 9) | (state.X3 + state.X15 >> (32 - 9));
                    state.X11 ^= (state.X7 + state.X3 << 13) | (state.X7 + state.X3 >> (32 - 13));
                    state.X15 ^= (state.X11 + state.X7 << 18) | (state.X11 + state.X7 >> (32 - 18));                    
                    #endregion
                    
                    #region ColumnRound
                    // column 0
                    state.X1 ^= (state.X0 + state.X3 << 7) | (state.X0 + state.X3 >> (32 - 7));
                    state.X2 ^= (state.X1 + state.X0 << 9) | (state.X1 + state.X0 >> (32 - 9));
                    state.X3 ^= (state.X2 + state.X1 << 13) | (state.X2 + state.X1 >> (32 - 13));
                    state.X0 ^= (state.X3 + state.X2 << 18) | (state.X3 + state.X2 >> (32 - 18));

                    // column 1
                    state.X6 ^= (state.X5 + state.X4 << 7) | (state.X5 + state.X4 >> (32 - 7));
                    state.X7 ^= (state.X6 + state.X5 << 9) | (state.X6 + state.X5 >> (32 - 9));
                    state.X4 ^= (state.X7 + state.X6 << 13) | (state.X7 + state.X6 >> (32 - 13));                    
                    state.X5 ^= (state.X4 + state.X7 << 18) | (state.X4 + state.X7 >> (32 - 18));

                    // column 2
                    state.X11 ^= (state.X10 + state.X9 << 7) | (state.X10 + state.X9 >> (32 - 7));
                    state.X8 ^= (state.X11 + state.X10 << 9) | (state.X11 + state.X10 >> (32 - 9));
                    state.X9 ^= (state.X8 + state.X11 << 13) | (state.X8 + state.X11 >> (32 - 13));
                    state.X10 ^= (state.X9 + state.X8 << 18) | (state.X9 + state.X8 >> (32 - 18));

                    // column 3
                    state.X12 ^= (state.X15 + state.X14 << 7) | (state.X15 + state.X14 >> (32 - 7));
                    state.X13 ^= (state.X12 + state.X15 << 9) | (state.X12 + state.X15 >> (32 - 9));
                    state.X14 ^= (state.X13 + state.X12 << 13) | (state.X13 + state.X12 >> (32 - 13));
                    state.X15 ^= (state.X14 + state.X13 << 18) | (state.X14 + state.X13 >> (32 - 18));
                    #endregion
                }
            }
        }
    }
}
