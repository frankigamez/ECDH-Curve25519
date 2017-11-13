using System;

namespace ECDH25519.Algorithm.Core
{
    internal struct FieldElement
    {
        internal int X0;
        internal int X1;
        internal int X2;
        internal int X3;
        internal int X4;
        internal int X5;
        internal int X6;
        internal int X7;
        internal int X8;
        internal int X9;

        internal FieldElement(params int[] elements)
        {
            if (elements.Length != 10) 
                throw new ArgumentException($"{nameof(elements)} must have 10 elements");
            
            X0 = elements[0];
            X1 = elements[1];
            X2 = elements[2];
            X3 = elements[3];
            X4 = elements[4];
            X5 = elements[5];
            X6 = elements[6];
            X7 = elements[7];
            X8 = elements[8];
            X9 = elements[9];
        }
    }
}
