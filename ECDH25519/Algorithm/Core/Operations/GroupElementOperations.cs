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
        public static GroupElementP3 ScalarmultBase(byte[] a, int offset)
        {
	        GroupElementP3 h;
	        
	        var e = new sbyte[64];
	        sbyte carry;
	        GroupElementP1P1 r;
	        GroupElementP2 s;
	        GroupElementPreComp t;
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
		        h = P1p1ToP3(ref r);
	        }

	        r = P3Dbl(ref h); 
	        s = P1p1ToP2(ref r);
	        
	        r = P2Dbl(ref s); 
	        s = P1p1ToP2(ref r);
	        
	        r = P2Dbl(ref s); 
	        s = P1p1ToP2(ref r);
	        
	        r = P2Dbl(ref s); 
	        h = P1p1ToP3(ref r);

	        for (i = 0; i < 64; i += 2)
	        {
		        t = Select(i / 2, e[i]);
		        r = Madd(ref h, ref t); 
		        h = P1p1ToP3(ref r);
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
	    private static void Cmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
	    {
		    FieldElementOperations.Cmov(ref t.yplusx, ref u.yplusx, b);
		    FieldElementOperations.Cmov(ref t.yminusx, ref u.yminusx, b);
		    FieldElementOperations.Cmov(ref t.xy2d, ref u.xy2d, b);
	    }	    
	    private static GroupElementPreComp Select(int pos, sbyte b)
	    {
		    GroupElementPreComp t;
		    
		    GroupElementPreComp minust;
		    var bnegative = Negative(b);
		    var babs = (byte)(b - (((-bnegative) & b) << 1));

		    t = new GroupElementPreComp
		    {
			    yplusx = FieldElementOperations.Set1(),
			    yminusx = FieldElementOperations.Set1(),
			    xy2d = FieldElementOperations.Set0()
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
		    minust.yplusx = t.yminusx;
		    minust.yminusx = t.yplusx;
		    minust.xy2d = FieldElementOperations.Negate(ref t.xy2d);
		    Cmov(ref t, ref minust, bnegative);

		    return t;
	    }

	   	    
	    private static GroupElementP1P1 P3Dbl(ref GroupElementP3 p)
	    {
		    //r = 2 * p
		    var q =new GroupElementP2
		    {
			    //r = p
			    X = p.X,
			    Y = p.Y,
			    Z = p.Z
		    };
		    return P2Dbl(ref q);
	    }
	    	   
	    
	    private static GroupElementP1P1 P2Dbl(ref GroupElementP2 p)
	    {
		    var r = new GroupElementP1P1();

		    /* XX=X1^2 */
		    /* asm 1: fe_sq(>XX=fe#1,<X1=fe#11); */
		    /* asm 2: fe_sq(>XX=r.X,<X1=p.X); */
		    r.X = FieldElementOperations.Squared(ref p.X);

		    /* YY=Y1^2 */
		    /* asm 1: fe_sq(>YY=fe#3,<Y1=fe#12); */
		    /* asm 2: fe_sq(>YY=r.Z,<Y1=p.Y); */
		    r.Z = FieldElementOperations.Squared(ref p.Y);

		    /* B=2*Z1^2 */
		    /* asm 1: fe_sq2(>B=fe#4,<Z1=fe#13); */
		    /* asm 2: fe_sq2(>B=r.T,<Z1=p.Z); */
		    r.T = FieldElementOperations.DoubleSquare(ref p.Z);

		    /* A=X1+Y1 */
		    /* asm 1: fe_add(>A=fe#2,<X1=fe#11,<Y1=fe#12); */
		    /* asm 2: fe_add(>A=r.Y,<X1=p.X,<Y1=p.Y); */
		    r.Y = FieldElementOperations.Add(ref p.X, ref p.Y);

		    /* AA=A^2 */
		    /* asm 1: fe_sq(>AA=fe#5,<A=fe#2); */
		    /* asm 2: fe_sq(>AA=t0,<A=r.Y); */
		    var t0 = FieldElementOperations.Squared(ref r.Y);

		    /* Y3=YY+XX */
		    /* asm 1: fe_add(>Y3=fe#2,<YY=fe#3,<XX=fe#1); */
		    /* asm 2: fe_add(>Y3=r.Y,<YY=r.Z,<XX=r.X); */
		    r.Y = FieldElementOperations.Add(ref r.Z, ref r.X);

		    /* Z3=YY-XX */
		    /* asm 1: fe_sub(>Z3=fe#3,<YY=fe#3,<XX=fe#1); */
		    /* asm 2: fe_sub(>Z3=r.Z,<YY=r.Z,<XX=r.X); */
		    r.Z = FieldElementOperations.Sub(ref r.Z, ref r.X);

		    /* X3=AA-Y3 */
		    /* asm 1: fe_sub(>X3=fe#1,<AA=fe#5,<Y3=fe#2); */
		    /* asm 2: fe_sub(>X3=r.X,<AA=t0,<Y3=r.Y); */
			r.X =FieldElementOperations.Sub(ref t0, ref r.Y);

		    /* T3=B-Z3 */
		    /* asm 1: fe_sub(>T3=fe#4,<B=fe#4,<Z3=fe#3); */
		    /* asm 2: fe_sub(>T3=r.T,<B=r.T,<Z3=r.Z); */
		    r.T = FieldElementOperations.Sub(ref r.T, ref r.Z);
		    
		    return r;
	    }
	    	   
	    private static GroupElementP3 P1p1ToP3(ref GroupElementP1P1 p) => new GroupElementP3
	    {
		    X = FieldElementOperations.Multiply(ref p.X, ref p.T),
		    Y = FieldElementOperations.Multiply(ref p.Y, ref p.Z),
		    Z = FieldElementOperations.Multiply(ref p.Z, ref p.T),
		    T = FieldElementOperations.Multiply(ref p.X, ref p.Y)
	    };

	    
	    private static GroupElementP2 P1p1ToP2(ref GroupElementP1P1 p) => new GroupElementP2
	    {
		    X = FieldElementOperations.Multiply(ref p.X, ref p.T),
		    Y = FieldElementOperations.Multiply(ref p.Y, ref p.Z),
		    Z = FieldElementOperations.Multiply(ref p.Z, ref p.T)
	    };


	    private static GroupElementP1P1 Madd(ref GroupElementP3 p, ref GroupElementPreComp q)
		{
			var r = new GroupElementP1P1();

			/* YpX1 = Y1+X1 */
			/* asm 1: fe_add(>YpX1=fe#1,<Y1=fe#12,<X1=fe#11); */
			/* asm 2: fe_add(>YpX1=r.X,<Y1=p.Y,<X1=p.X); */
			r.X = FieldElementOperations.Add(ref p.Y, ref p.X);

			/* YmX1 = Y1-X1 */
			/* asm 1: fe_sub(>YmX1=fe#2,<Y1=fe#12,<X1=fe#11); */
			/* asm 2: fe_sub(>YmX1=r.Y,<Y1=p.Y,<X1=p.X); */
			r.Y = FieldElementOperations.Sub(ref p.Y, ref p.X);

			/* A = YpX1*ypx2 */
			/* asm 1: fe_mul(>A=fe#3,<YpX1=fe#1,<ypx2=fe#15); */
			/* asm 2: fe_mul(>A=r.Z,<YpX1=r.X,<ypx2=q.yplusx); */
			r.Z = FieldElementOperations.Multiply(ref r.X, ref q.yplusx);

			/* B = YmX1*ymx2 */
			/* asm 1: fe_mul(>B=fe#2,<YmX1=fe#2,<ymx2=fe#16); */
			/* asm 2: fe_mul(>B=r.Y,<YmX1=r.Y,<ymx2=q.yminusx); */
			r.Y = FieldElementOperations.Multiply(ref r.Y, ref q.yminusx);

			/* C = xy2d2*T1 */
			/* asm 1: fe_mul(>C=fe#4,<xy2d2=fe#17,<T1=fe#14); */
			/* asm 2: fe_mul(>C=r.T,<xy2d2=q.xy2d,<T1=p.T); */
			r.T = FieldElementOperations.Multiply(ref q.xy2d, ref p.T);

			/* D = 2*Z1 */
			/* asm 1: fe_add(>D=fe#5,<Z1=fe#13,<Z1=fe#13); */
			/* asm 2: fe_add(>D=t0,<Z1=p.Z,<Z1=p.Z); */
			var t0 = FieldElementOperations.Add(ref p.Z, ref p.Z);

			/* X3 = A-B */
			/* asm 1: fe_sub(>X3=fe#1,<A=fe#3,<B=fe#2); */
			/* asm 2: fe_sub(>X3=r.X,<A=r.Z,<B=r.Y); */
			r.X = FieldElementOperations.Sub(ref r.Z, ref r.Y);

			/* Y3 = A+B */
			/* asm 1: fe_add(>Y3=fe#2,<A=fe#3,<B=fe#2); */
			/* asm 2: fe_add(>Y3=r.Y,<A=r.Z,<B=r.Y); */
			r.Y = FieldElementOperations.Add(ref r.Z, ref r.Y);

			/* Z3 = D+C */
			/* asm 1: fe_add(>Z3=fe#3,<D=fe#5,<C=fe#4); */
			/* asm 2: fe_add(>Z3=r.Z,<D=t0,<C=r.T); */
			r.Z = FieldElementOperations.Add(ref t0, ref r.T);

			/* T3 = D-C */
			/* asm 1: fe_sub(>T3=fe#4,<D=fe#5,<C=fe#4); */
			/* asm 2: fe_sub(>T3=r.T,<D=t0,<C=r.T); */
			r.T = FieldElementOperations.Sub(ref t0, ref r.T);
		
			return r;
		}
    }
}