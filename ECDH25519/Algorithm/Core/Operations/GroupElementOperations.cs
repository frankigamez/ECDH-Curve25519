using ECDH25519.Algorithm.Core.GroupElements;

namespace ECDH25519.Algorithm.Core.Operations
{
    internal static class GroupElementsOperations
    {                       
        /// <summary>
        /// h = a * B
        /// where a = a[0]+256*a[1]+...+256^31 a[31]
        /// B is the Ed25519 base point (x,4/5) with x positive.
        /// 
        /// Preconditions:
        /// a[31] <= 127
        /// </summary>
        /// <param name="a"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        internal static GroupElementP3 ScalarMultiplicationBase(byte[] a, int offset = 0)
        {
	        GroupElementP3 h;
	        
	        var e = new sbyte[64];
	        sbyte carry;
	        GroupElementP1 r;
	        GroupElementP2 s;
	        GroupElementP4 t;
	        int i;

	        for (i = 0; i < 32; ++i)
	        {
		        e[2 * i + 0] = (sbyte)((a[offset + i] >> 0) & 15);
		        e[2 * i + 1] = (sbyte)((a[offset + i] >> 4) & 15);
	        }
	        /* each e[i] is between 0 and 15 */
	        /* e[63] is between 0 and 7 */

	        carry = 0;
	        for (i = 0; i < 63; ++i)
	        {
		        e[i] += carry;
		        carry = (sbyte)(e[i] + 8);
		        carry >>= 4;
		        e[i] -= (sbyte)(carry << 4);
	        }
	        e[63] += carry;
	        /* each e[i] is between -8 and 8 */

	        h = new GroupElementP3
	        {
		        X = FieldElementOperations.Set0(),
		        Y = FieldElementOperations.Set1(),
		        Z = FieldElementOperations.Set1(),
		        T = FieldElementOperations.Set0()
	        };
	        
	        for (i = 1; i < 64; i += 2)
	        {
		        t = Select(i / 2, e[i]);
		        r = Madd(ref h, ref t); 
		        h = P1ToP3(ref r);
	        }

	        r = P3ToP1(ref h); 
	        s = P1ToP2(ref r);
	        
	        r = P2ToP1(ref s); 
	        s = P1ToP2(ref r);
	        
	        r = P2ToP1(ref s); 
	        s = P1ToP2(ref r);
	        
	        r = P2ToP1(ref s); 
	        h = P1ToP3(ref r);

	        for (i = 0; i < 64; i += 2)
	        {
		        t = Select(i / 2, e[i]);
		        r = Madd(ref h, ref t); 
		        h = P1ToP3(ref r);
	        }

	        return h;
        }
	   	    
	    private static byte Equal(byte b, byte c)
	    {
		    var ub = b;
		    var uc = c;
		    var x = (byte)(ub ^ uc); /* 0: yes; 1..255: no */
		    uint y = x; /* 0: yes; 1..255: no */
		    unchecked { y -= 1; } /* 4294967295: yes; 0..254: no */
		    y >>= 31; /* 1: yes; 0: no */
		    return (byte)y;
	    }
	    
	    private static byte Negative(sbyte b)
	    {
		    var x = unchecked((ulong)b); /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
		    x >>= 63; /* 1: yes; 0: no */
		    return (byte)x;
	    }
	    
	    private static void Cmov(ref GroupElementP4 t, ref GroupElementP4 u, byte b)
	    {
		    FieldElementOperations.Mov(ref t.YplusX, ref u.YplusX, b);
		    FieldElementOperations.Mov(ref t.YminusX, ref u.YminusX, b);
		    FieldElementOperations.Mov(ref t.XY2D, ref u.XY2D, b);
	    }	    
	    
	    private static GroupElementP4 Select(int pos, sbyte b)
	    {
		    GroupElementP4 t;
		    
		    GroupElementP4 minust;
		    var bnegative = Negative(b);
		    var babs = (byte)(b - ((-bnegative & b) << 1));

		    t = new GroupElementP4
		    {
			    YplusX = FieldElementOperations.Set1(),
			    YminusX = FieldElementOperations.Set1(),
			    XY2D = FieldElementOperations.Set0()
		    };
		    
		    var table = LookupTables.Base[pos];
		    Cmov(ref t, ref table[0], Equal(babs, 1));
		    Cmov(ref t, ref table[1], Equal(babs, 2));
		    Cmov(ref t, ref table[2], Equal(babs, 3));
		    Cmov(ref t, ref table[3], Equal(babs, 4));
		    Cmov(ref t, ref table[4], Equal(babs, 5));
		    Cmov(ref t, ref table[5], Equal(babs, 6));
		    Cmov(ref t, ref table[6], Equal(babs, 7));
		    Cmov(ref t, ref table[7], Equal(babs, 8));
		    minust.YplusX = t.YminusX;
		    minust.YminusX = t.YplusX;
		    minust.XY2D = FieldElementOperations.Negate(ref t.XY2D);
		    Cmov(ref t, ref minust, bnegative);

		    return t;
	    }
	   	    
	    private static GroupElementP1 P3ToP1(ref GroupElementP3 p)
	    {
		    //r = 2 * p
		    var q =new GroupElementP2
		    {
			    //r = p
			    X = p.X,
			    Y = p.Y,
			    Z = p.Z
		    };
		    return P2ToP1(ref q);
	    }
	    	   	    
	    private static GroupElementP1 P2ToP1(ref GroupElementP2 p)
	    {
		    var r = new GroupElementP1();

		    /* XX=X1^2 */
		    r.X = FieldElementOperations.Squared(ref p.X);

		    /* YY=Y1^2 */
		    r.Z = FieldElementOperations.Squared(ref p.Y);

		    /* B=2*Z1^2 */
		    r.T = FieldElementOperations.DoubleSquare(ref p.Z);

		    /* A=X1+Y1 */
		    r.Y = FieldElementOperations.Add(ref p.X, ref p.Y);

		    /* AA=A^2 */
		    var t0 = FieldElementOperations.Squared(ref r.Y);

		    /* Y3=YY+XX */
		    r.Y = FieldElementOperations.Add(ref r.Z, ref r.X);

		    /* Z3=YY-XX */
		    r.Z = FieldElementOperations.Sub(ref r.Z, ref r.X);

		    /* X3=AA-Y3 */
			r.X =FieldElementOperations.Sub(ref t0, ref r.Y);

		    /* T3=B-Z3 */
		    r.T = FieldElementOperations.Sub(ref r.T, ref r.Z);
		    
		    return r;
	    }
	    	   
	    private static GroupElementP3 P1ToP3(ref GroupElementP1 p) => new GroupElementP3
	    {
		    X = FieldElementOperations.Multiplication(ref p.X, ref p.T),
		    Y = FieldElementOperations.Multiplication(ref p.Y, ref p.Z),
		    Z = FieldElementOperations.Multiplication(ref p.Z, ref p.T),
		    T = FieldElementOperations.Multiplication(ref p.X, ref p.Y)
	    };
	    
	    private static GroupElementP2 P1ToP2(ref GroupElementP1 p) => new GroupElementP2
	    {
		    X = FieldElementOperations.Multiplication(ref p.X, ref p.T),
		    Y = FieldElementOperations.Multiplication(ref p.Y, ref p.Z),
		    Z = FieldElementOperations.Multiplication(ref p.Z, ref p.T)
	    };

	    private static GroupElementP1 Madd(ref GroupElementP3 p, ref GroupElementP4 q)
		{						
			var t0 = FieldElementOperations.Add(ref p.Z, ref p.Z); /* D = 2*Z1 */
			var r = new GroupElementP1();
			
			/* YpX1 = Y1+X1 */
			r.X = FieldElementOperations.Add(ref p.Y, ref p.X);

			/* YmX1 = Y1-X1 */
			r.Y = FieldElementOperations.Sub(ref p.Y, ref p.X);

			/* A = YpX1*ypx2 */
			r.Z = FieldElementOperations.Multiplication(ref r.X, ref q.YplusX);

			/* B = YmX1*ymx2 */
			r.Y = FieldElementOperations.Multiplication(ref r.Y, ref q.YminusX);

			/* C = xy2d2*T1 */
			r.T = FieldElementOperations.Multiplication(ref q.XY2D, ref p.T);
			
			/* X3 = A-B */
			r.X = FieldElementOperations.Sub(ref r.Z, ref r.Y);

			/* Y3 = A+B */
			r.Y = FieldElementOperations.Add(ref r.Z, ref r.Y);

			/* Z3 = D+C */
			r.Z = FieldElementOperations.Add(ref t0, ref r.T);

			/* T3 = D-C */
			r.T = FieldElementOperations.Sub(ref t0, ref r.T);
		
			return r;
		}
    }
}