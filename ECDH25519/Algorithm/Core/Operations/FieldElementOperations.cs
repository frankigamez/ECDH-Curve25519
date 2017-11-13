namespace ECDH25519.Algorithm.Core.Operations
{
	internal static class FieldElementOperations
	{
		public static FieldElement Set0() => new FieldElement();

		
		public static FieldElement Set1() => new FieldElement {X0 = 1};

		
		/// <summary>
		/// h = f + g
		/// Can overlap h with f or g.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		///
		/// Postconditions:
		/// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		/// </summary>
		/// <param name="f"></param>
		/// <param name="g"></param>
		internal static FieldElement Add(ref FieldElement f, ref FieldElement g) => new FieldElement
		{
			X0 = f.X0 + g.X0,
			X1 = f.X1 + g.X1,
			X2 = f.X2 + g.X2,
			X3 = f.X3 + g.X3,
			X4 = f.X4 + g.X4,
			X5 = f.X5 + g.X5,
			X6 = f.X6 + g.X6,
			X7 = f.X7 + g.X7,
			X8 = f.X8 + g.X8,
			X9 = f.X9 + g.X9
		};

		
		/// <summary>
		/// Replace (f,g) with (g,g) if b == 1;
		/// replace (f,g) with (f,g) if b == 0.
		///
		/// Preconditions: b in {0,1}.
		/// </summary>
		/// <param name="f"></param>
		/// <param name="g"></param>
		/// <param name="b"></param>
		internal static void Cmov(ref FieldElement f, ref FieldElement g, int b)
		{
			b = -b;
			f.X0 = f.X0 ^ ((f.X0 ^ g.X0) & b);
			f.X1 = f.X1 ^ ((f.X1 ^ g.X1) & b);
			f.X2 = f.X2 ^ ((f.X2 ^ g.X2) & b);
			f.X3 = f.X3 ^ ((f.X3 ^ g.X3) & b);
			f.X4 = f.X4 ^ ((f.X4 ^ g.X4) & b);
			f.X5 = f.X5 ^ ((f.X5 ^ g.X5) & b);
			f.X6 = f.X6 ^ ((f.X6 ^ g.X6) & b);
			f.X7 = f.X7 ^ ((f.X7 ^ g.X7) & b);
			f.X8 = f.X8 ^ ((f.X8 ^ g.X8) & b);
			f.X9 = f.X9 ^ ((f.X9 ^ g.X9) & b);			
		}
		
		
		/// <summary>
		/// Replace (f,g) with (g,f) if b == 1;
		/// replace (f,g) with (f,g) if b == 0.
		///
		/// Preconditions: b in {0,1}.
		/// </summary>
		/// <param name="f"></param>
		/// <param name="g"></param>
		/// <param name="b"></param>
		public static void Cswap(ref FieldElement f, ref FieldElement g, uint b)
		{			
			var negb = unchecked((int)-b);					
			var x0 = (f.X0 ^ g.X0) & negb;
			var x1 = (f.X1 ^ g.X1) & negb;
			var x2 = (f.X2 ^ g.X2) & negb;
			var x3 = (f.X3 ^ g.X3) & negb;
			var x4 = (f.X4 ^ g.X4) & negb;
			var x5 = (f.X5 ^ g.X5) & negb;
			var x6 = (f.X6 ^ g.X6) & negb;
			var x7 = (f.X7 ^ g.X7) & negb;
			var x8 = (f.X8 ^ g.X8) & negb;
			var x9 = (f.X9 ^ g.X9) & negb;
			
			f.X0 = f.X0 ^ x0;
			f.X1 = f.X1 ^ x1;
			f.X2 = f.X2 ^ x2;
			f.X3 = f.X3 ^ x3;
			f.X4 = f.X4 ^ x4;
			f.X5 = f.X5 ^ x5;
			f.X6 = f.X6 ^ x6;
			f.X7 = f.X7 ^ x7;
			f.X8 = f.X8 ^ x8;
			f.X9 = f.X9 ^ x9;
			g.X0 = g.X0 ^ x0;
			g.X1 = g.X1 ^ x1;
			g.X2 = g.X2 ^ x2;
			g.X3 = g.X3 ^ x3;
			g.X4 = g.X4 ^ x4;
			g.X5 = g.X5 ^ x5;
			g.X6 = g.X6 ^ x6;
			g.X7 = g.X7 ^ x7;
			g.X8 = g.X8 ^ x8;
			g.X9 = g.X9 ^ x9;
		}
		
		
		/// <summary>
		/// Does NOT ignore top bit
		/// </summary>
		/// <param name="data"></param>
		/// <param name="offset"></param>
		/// <returns></returns>
		internal static FieldElement FromBytes(byte[] data, int offset)
		{
			long Load3(byte[] data3, int offset3)
			{
				uint result;
				result = data3[offset3 + 0];
				for (var i = 1; i < 3; i++)
					result |= (uint) data3[offset3 + i] << 8 * i;
				return result;
			}

			long Load4(byte[] data4, int offset4)
			{
				uint result;
				result = data4[offset4 + 0];
				for (var i = 1; i < 4; i++)
					result |= (uint) data4[offset4 + i] << 8 * i;
				return result;
			}

			var h0 = Load4(data, offset);
			var h1 = Load3(data, offset + 4) << 6;
			var h2 = Load3(data, offset + 7) << 5;
			var h3 = Load3(data, offset + 10) << 3;
			var h4 = Load3(data, offset + 13) << 2;
			var h5 = Load4(data, offset + 16);
			var h6 = Load3(data, offset + 20) << 7;
			var h7 = Load3(data, offset + 23) << 5;
			var h8 = Load3(data, offset + 26) << 4;
			var h9 = Load3(data, offset + 29) << 2;
			
			var carry1 = (h1 + (1 << 24)) >> 25; 
			h2 += carry1; 
			h1 -= carry1 << 25;
			
			var carry9 = (h9 + (1 << 24)) >> 25; 
			h0 += carry9 * 19; 
			h9 -= carry9 << 25;
			
			var carry3 = (h3 + (1 << 24)) >> 25; 
			h4 += carry3; 
			h3 -= carry3 << 25;
			
			var carry5 = (h5 + (1 << 24)) >> 25; 
			h6 += carry5; 
			h5 -= carry5 << 25;
			
			var carry7 = (h7 + (1 << 24)) >> 25; 
			h8 += carry7; 
			h7 -= carry7 << 25;

			var carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;
			
			var carry2 = (h2 + (1 << 25)) >> 26; 
			h3 += carry2; 
			h2 -= carry2 << 26;
			
			var carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;
			
			var carry6 = (h6 + (1 << 25)) >> 26; 
			h7 += carry6; 
			h6 -= carry6 << 26;
			
			var carry8 = (h8 + (1 << 25)) >> 26; 
			h9 += carry8; 
			h8 -= carry8 << 26;
			
			return new FieldElement
			{
				X0 = (int) h0,
				X1 = (int) h1,
				X2 = (int) h2,
				X3 = (int) h3,
				X4 = (int) h4,
				X5 = (int) h5,
				X6 = (int) h6,
				X7 = (int) h7,
				X8 = (int) h8,
				X9 = (int) h9
			};
		}
		
		
		internal static FieldElement Invert(ref FieldElement z)
		{
			int i;

			/* z2 = z1^2^1 */
			/* asm 1: fe_sq(>z2=fe#1,<z1=fe#11); for (i = 1;i < 1;++i) fe_sq(>z2=fe#1,>z2=fe#1); */
			/* asm 2: fe_sq(>z2=t0,<z1=z); for (i = 1;i < 1;++i) fe_sq(>z2=t0,>z2=t0); */
			var t0 = Squared(ref z); //for (i = 1; i < 1; ++i) fe_sq(out t0, ref t0);

			/* z8 = z2^2^2 */
			/* asm 1: fe_sq(>z8=fe#2,<z2=fe#1); for (i = 1;i < 2;++i) fe_sq(>z8=fe#2,>z8=fe#2); */
			/* asm 2: fe_sq(>z8=t1,<z2=t0); for (i = 1;i < 2;++i) fe_sq(>z8=t1,>z8=t1); */
			var t1 = Squared(ref t0); 
			for (i = 1; i < 2; ++i) 
				t1 = Squared(ref t1);

			/* z9 = z1*z8 */
			/* asm 1: fe_mul(>z9=fe#2,<z1=fe#11,<z8=fe#2); */
			/* asm 2: fe_mul(>z9=t1,<z1=z,<z8=t1); */
			t1 = Multiply(ref z, ref t1);

			/* z11 = z2*z9 */
			/* asm 1: fe_mul(>z11=fe#1,<z2=fe#1,<z9=fe#2); */
			/* asm 2: fe_mul(>z11=t0,<z2=t0,<z9=t1); */
			t0 = Multiply(ref t0, ref t1);

			/* z22 = z11^2^1 */
			/* asm 1: fe_sq(>z22=fe#3,<z11=fe#1); for (i = 1;i < 1;++i) fe_sq(>z22=fe#3,>z22=fe#3); */
			/* asm 2: fe_sq(>z22=t2,<z11=t0); for (i = 1;i < 1;++i) fe_sq(>z22=t2,>z22=t2); */
			var t2 = Squared(ref t0); //for (i = 1; i < 1; ++i) fe_sq(out t2, ref t2);

			/* z_5_0 = z9*z22 */
			/* asm 1: fe_mul(>z_5_0=fe#2,<z9=fe#2,<z22=fe#3); */
			/* asm 2: fe_mul(>z_5_0=t1,<z9=t1,<z22=t2); */
			t1 = Multiply(ref t1, ref t2);

			/* z_10_5 = z_5_0^2^5 */
			/* asm 1: fe_sq(>z_10_5=fe#3,<z_5_0=fe#2); for (i = 1;i < 5;++i) fe_sq(>z_10_5=fe#3,>z_10_5=fe#3); */
			/* asm 2: fe_sq(>z_10_5=t2,<z_5_0=t1); for (i = 1;i < 5;++i) fe_sq(>z_10_5=t2,>z_10_5=t2); */
			t2 = Squared(ref t1); 
			for (i = 1; i < 5; ++i) 
				t2 = Squared(ref t2);

			/* z_10_0 = z_10_5*z_5_0 */
			/* asm 1: fe_mul(>z_10_0=fe#2,<z_10_5=fe#3,<z_5_0=fe#2); */
			/* asm 2: fe_mul(>z_10_0=t1,<z_10_5=t2,<z_5_0=t1); */
			t1 = Multiply(ref t2, ref t1);

			/* z_20_10 = z_10_0^2^10 */
			/* asm 1: fe_sq(>z_20_10=fe#3,<z_10_0=fe#2); for (i = 1;i < 10;++i) fe_sq(>z_20_10=fe#3,>z_20_10=fe#3); */
			/* asm 2: fe_sq(>z_20_10=t2,<z_10_0=t1); for (i = 1;i < 10;++i) fe_sq(>z_20_10=t2,>z_20_10=t2); */
			t2 = Squared(ref t1); 
			for (i = 1; i < 10; ++i) 
				t2 = Squared(ref t2);

			/* z_20_0 = z_20_10*z_10_0 */
			/* asm 1: fe_mul(>z_20_0=fe#3,<z_20_10=fe#3,<z_10_0=fe#2); */
			/* asm 2: fe_mul(>z_20_0=t2,<z_20_10=t2,<z_10_0=t1); */
			t2 = Multiply(ref t2, ref t1);

			/* z_40_20 = z_20_0^2^20 */
			/* asm 1: fe_sq(>z_40_20=fe#4,<z_20_0=fe#3); for (i = 1;i < 20;++i) fe_sq(>z_40_20=fe#4,>z_40_20=fe#4); */
			/* asm 2: fe_sq(>z_40_20=t3,<z_20_0=t2); for (i = 1;i < 20;++i) fe_sq(>z_40_20=t3,>z_40_20=t3); */
			var t3 = Squared(ref t2); 
			for (i = 1; i < 20; ++i) 
				t3 = Squared(ref t3);

			/* z_40_0 = z_40_20*z_20_0 */
			/* asm 1: fe_mul(>z_40_0=fe#3,<z_40_20=fe#4,<z_20_0=fe#3); */
			/* asm 2: fe_mul(>z_40_0=t2,<z_40_20=t3,<z_20_0=t2); */
			t2 = Multiply(ref t3, ref t2);

			/* z_50_10 = z_40_0^2^10 */
			/* asm 1: fe_sq(>z_50_10=fe#3,<z_40_0=fe#3); for (i = 1;i < 10;++i) fe_sq(>z_50_10=fe#3,>z_50_10=fe#3); */
			/* asm 2: fe_sq(>z_50_10=t2,<z_40_0=t2); for (i = 1;i < 10;++i) fe_sq(>z_50_10=t2,>z_50_10=t2); */
			t2 = Squared(ref t2); 
			for (i = 1; i < 10; ++i) 
				t2 = Squared(ref t2);

			/* z_50_0 = z_50_10*z_10_0 */
			/* asm 1: fe_mul(>z_50_0=fe#2,<z_50_10=fe#3,<z_10_0=fe#2); */
			/* asm 2: fe_mul(>z_50_0=t1,<z_50_10=t2,<z_10_0=t1); */
			t1 = Multiply(ref t2, ref t1);

			/* z_100_50 = z_50_0^2^50 */
			/* asm 1: fe_sq(>z_100_50=fe#3,<z_50_0=fe#2); for (i = 1;i < 50;++i) fe_sq(>z_100_50=fe#3,>z_100_50=fe#3); */
			/* asm 2: fe_sq(>z_100_50=t2,<z_50_0=t1); for (i = 1;i < 50;++i) fe_sq(>z_100_50=t2,>z_100_50=t2); */
			t2 = Squared(ref t1); 
			for (i = 1; i < 50; ++i) 
				t2 = Squared(ref t2);

			/* z_100_0 = z_100_50*z_50_0 */
			/* asm 1: fe_mul(>z_100_0=fe#3,<z_100_50=fe#3,<z_50_0=fe#2); */
			/* asm 2: fe_mul(>z_100_0=t2,<z_100_50=t2,<z_50_0=t1); */
			t2 = Multiply(ref t2, ref t1);

			/* z_200_100 = z_100_0^2^100 */
			/* asm 1: fe_sq(>z_200_100=fe#4,<z_100_0=fe#3); for (i = 1;i < 100;++i) fe_sq(>z_200_100=fe#4,>z_200_100=fe#4); */
			/* asm 2: fe_sq(>z_200_100=t3,<z_100_0=t2); for (i = 1;i < 100;++i) fe_sq(>z_200_100=t3,>z_200_100=t3); */
			t3 = Squared(ref t2); 
			for (i = 1; i < 100; ++i) 
				t3 = Squared(ref t3);

			/* z_200_0 = z_200_100*z_100_0 */
			/* asm 1: fe_mul(>z_200_0=fe#3,<z_200_100=fe#4,<z_100_0=fe#3); */
			/* asm 2: fe_mul(>z_200_0=t2,<z_200_100=t3,<z_100_0=t2); */
			t2 = Multiply(ref t3, ref t2);

			/* z_250_50 = z_200_0^2^50 */
			/* asm 1: fe_sq(>z_250_50=fe#3,<z_200_0=fe#3); for (i = 1;i < 50;++i) fe_sq(>z_250_50=fe#3,>z_250_50=fe#3); */
			/* asm 2: fe_sq(>z_250_50=t2,<z_200_0=t2); for (i = 1;i < 50;++i) fe_sq(>z_250_50=t2,>z_250_50=t2); */
			t2 = Squared(ref t2); 
			for (i = 1; i < 50; ++i) 
				t2 = Squared(ref t2);

			/* z_250_0 = z_250_50*z_50_0 */
			/* asm 1: fe_mul(>z_250_0=fe#2,<z_250_50=fe#3,<z_50_0=fe#2); */
			/* asm 2: fe_mul(>z_250_0=t1,<z_250_50=t2,<z_50_0=t1); */
			t1 = Multiply(ref t2, ref t1);

			/* z_255_5 = z_250_0^2^5 */
			/* asm 1: fe_sq(>z_255_5=fe#2,<z_250_0=fe#2); for (i = 1;i < 5;++i) fe_sq(>z_255_5=fe#2,>z_255_5=fe#2); */
			/* asm 2: fe_sq(>z_255_5=t1,<z_250_0=t1); for (i = 1;i < 5;++i) fe_sq(>z_255_5=t1,>z_255_5=t1); */
			t1 = Squared(ref t1); 
			for (i = 1; i < 5; ++i) 
				t1 = Squared(ref t1);

			/* z_255_21 = z_255_5*z11 */
			/* asm 1: fe_mul(>z_255_21=fe#12,<z_255_5=fe#2,<z11=fe#1); */
			/* asm 2: fe_mul(>z_255_21=out,<z_255_5=t1,<z11=t0); */
			var result = Multiply(ref t1, ref t0);

			return result;
		}
		
				
		/// <summary>
		/// h = f * g
		/// Can overlap h with f or g.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
		/// |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
		/// </summary>		
		/// <param name="f"></param>
		/// <param name="g"></param>
		internal static FieldElement Multiply(ref FieldElement f, ref FieldElement g)
		{					
			/*
			Notes on implementation strategy:
	
			Using schoolbook multiplication. 
			Karatsuba would save a little in some cost models.
	
			Most multiplications by 2 and 19 are 32-bit precomputations;
			cheaper than 64-bit postcomputations.
	
			There is one remaining multiplication by 19 in the carry chain;
			one *19 precomputation can be merged into this,
			but the resulting data flow is considerably less clean.
	
			There are 12 carries below.
			10 of them are 2-way parallelizable and vectorizable.
			Can get away with 11 carries, but then data flow is much deeper.
	
			With tighter constraints on inputs can squeeze carries into int32.
			*/
			
			var h0 = f.X0 * (long)g.X0 + (2 * f.X1) * (long)(19 * g.X9) + f.X2 * (long)(19 * g.X8) + (2 * f.X3) * (long)(19 * g.X7) + f.X4 * (long)(19 * g.X6) + (2 * f.X5) * (long)(19 * g.X5) + f.X6 * (long)(19 * g.X4) + (2 * f.X7) * (long)(19 * g.X3) + f.X8 * (long)(19 * g.X2) + (2 * f.X9) * (long)(19 * g.X1);
			var h1 = f.X0 * (long)g.X1 + f.X1 * (long)g.X0 + f.X2 * (long)(19 * g.X9) + f.X3 * (long)(19 * g.X8) + f.X4 * (long)(19 * g.X7) + f.X5 * (long)(19 * g.X6) + f.X6 * (long)(19 * g.X5) + f.X7 * (long)(19 * g.X4) + f.X8 * (long)(19 * g.X3) + f.X9 * (long)(19 * g.X2);
			var h2 = f.X0 * (long)g.X2 + (2 * f.X1) * (long)g.X1 + f.X2 * (long)g.X0 + (2 * f.X3) * (long)(19 * g.X9) + f.X4 * (long)(19 * g.X8) + (2 * f.X5) * (long)(19 * g.X7) + f.X6 * (long)(19 * g.X6) + (2 * f.X7) * (long)(19 * g.X5) + f.X8 * (long)(19 * g.X4) + (2 * f.X9) * (long)(19 * g.X3);
			var h3 = f.X0 * (long)g.X3 + f.X1 * (long)g.X2 + f.X2 * (long)g.X1 + f.X3 * (long)g.X0 + f.X4 * (long)(19 * g.X9) + f.X5 * (long)(19 * g.X8) + f.X6 * (long)(19 * g.X7) + f.X7 * (long)(19 * g.X6) + f.X8 * (long)(19 * g.X5) + f.X9 * (long)(19 * g.X4);
			var h4 = f.X0 * (long)g.X4 + (2 * f.X1) * (long)g.X3 + f.X2 * (long)g.X2 + (2 * f.X3) * (long)g.X1 + f.X4 * (long)g.X0 + (2 * f.X5) * (long)(19 * g.X9) + f.X6 * (long)(19 * g.X8) + (2 * f.X7) * (long)(19 * g.X7) + f.X8 * (long)(19 * g.X6) + (2 * f.X9) * (long)(19 * g.X5);
			var h5 = f.X0 * (long)g.X5 + f.X1 * (long)g.X4 + f.X2 * (long)g.X3 + f.X3 * (long)g.X2 + f.X4 * (long)g.X1 + f.X5 * (long)g.X0 + f.X6 * (long)(19 * g.X9) + f.X7 * (long)(19 * g.X8) + f.X8 * (long)(19 * g.X7) + f.X9 * (long)(19 * g.X6);
			var h6 = f.X0 * (long)g.X6 + (2 * f.X1) * (long)g.X5 + f.X2 * (long)g.X4 + (2 * f.X3) * (long)g.X3 + f.X4 * (long)g.X2 + (2 * f.X5) * (long)g.X1 + f.X6 * (long)g.X0 + (2 * f.X7) * (long)(19 * g.X9) + f.X8 * (long)(19 * g.X8) + (2 * f.X9) * (long)(19 * g.X7);
			var h7 = f.X0 * (long)g.X7 + f.X1 * (long)g.X6 + f.X2 * (long)g.X5 + f.X3 * (long)g.X4 + f.X4 * (long)g.X3  + f.X5 * (long)g.X2 + f.X6 * (long)g.X1 + f.X7 * (long)g.X0 + f.X8 * (long)(19 * g.X9) + f.X9 * (long)(19 * g.X8);
			var h8 = f.X0 * (long)g.X8 + (2 * f.X1) * (long)g.X7 + f.X2 * (long)g.X6 + (2 * f.X3) * (long)g.X5 + f.X4 * (long)g.X4 + (2 * f.X5) * (long)g.X3 + f.X6 * (long)g.X2 + (2 * f.X7) * (long)g.X1 + f.X8 * (long)g.X0 + (2 * f.X9) * (long)(19 * g.X9);
			var h9 = f.X0 * (long)g.X9 + f.X1 * (long)g.X8 + f.X2 * (long)g.X7 + f.X3 * (long)g.X6 + f.X4 * (long)g.X5 + f.X5 * (long)g.X4 + f.X6 * (long)g.X3 + f.X7 * (long)g.X2 + f.X8 * (long)g.X1 + f.X9 * (long)g.X0;

			/*
			|h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
			  i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
			|h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
			  i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
			*/

			var carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0;  /* |h1| <= 1.71*2^59 */
			h0 -= carry0 << 26; /* |h0| <= 2^25 */
			
			var carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4;  /* |h5| <= 1.71*2^59 */
			h4 -= carry4 << 26;/* |h4| <= 2^25 */
			
			var carry1 = (h1 + (1 << 24)) >> 25; 
			h2 += carry1;  /* |h2| <= 1.41*2^60 */
			h1 -= carry1 << 25; /* |h1| <= 2^24; from now on fits into int32 */
			
			var carry5 = (h5 + (1 << 24)) >> 25; 
			h6 += carry5;  /* |h6| <= 1.41*2^60 */
			h5 -= carry5 << 25; /* |h5| <= 2^24; from now on fits into int32 */
	
			var carry2 = (h2 + (1 << 25)) >> 26; 
			h3 += carry2; /* |h3| <= 1.71*2^59 */
			h2 -= carry2 << 26; /* |h2| <= 2^25; from now on fits into int32 unchanged */
			
			var carry6 = (h6 + (1 << 25)) >> 26; 
			h7 += carry6; /* |h7| <= 1.71*2^59 */
			h6 -= carry6 << 26; /* |h6| <= 2^25; from now on fits into int32 unchanged */

			var carry3 = (h3 + (1 << 24)) >> 25; 
			h4 += carry3; /* |h4| <= 1.72*2^34 */
			h3 -= carry3 << 25; /* |h3| <= 2^24; from now on fits into int32 unchanged */
			var carry7 = (h7 + (1 << 24)) >> 25; 
			h8 += carry7; /* |h8| <= 1.41*2^60 */
			h7 -= carry7 << 25; /* |h7| <= 2^24; from now on fits into int32 unchanged */

			carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; /* |h5| <= 1.01*2^24 */
			h4 -= carry4 << 26; /* |h4| <= 2^25; from now on fits into int32 unchanged */
			
			var carry8 = (h8 + (1 << 25)) >> 26; 
			h9 += carry8; /* |h9| <= 1.71*2^59 */
			h8 -= carry8 << 26; /* |h8| <= 2^25; from now on fits into int32 unchanged */
			
			var carry9 = (h9 + (1 << 24)) >> 25; 
			h0 += carry9 * 19; /* |h0| <= 1.1*2^39 */
			h9 -= carry9 << 25; /* |h9| <= 2^24; from now on fits into int32 unchanged */
						
			carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; /* |h1| <= 1.01*2^24 */
			h0 -= carry0 << 26; /* |h0| <= 2^25; from now on fits into int32 unchanged */
						
			var h = new FieldElement
			{
				X0 = (int) h0,
				X1 = (int) h1,
				X2 = (int) h2,
				X3 = (int) h3,
				X4 = (int) h4,
				X5 = (int) h5,
				X6 = (int) h6,
				X7 = (int) h7,
				X8 = (int) h8,
				X9 = (int) h9
			};
			return h;
		}
		
		
		/// <summary>
		/// h = -f
		/// 
		/// Preconditions:
		/// |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// </summary>
		/// <param name="h"></param>
		/// <param name="f"></param>
		internal static FieldElement Negate(ref FieldElement f) => new FieldElement
		{
			X0 = -f.X0,
			X1 = -f.X1,
			X2 = -f.X2,
			X3 = -f.X3,
			X4 = -f.X4,
			X5 = -f.X5,
			X6 = -f.X6,
			X7 = -f.X7,
			X8 = -f.X8,
			X9 = -f.X9
		};
		
		
		/// <summary>
		/// h = f - g
		/// Can overlap h with f or g.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		/// </summary>
		/// <param name="h"></param>
		/// <param name="f"></param>
		/// <param name="g"></param>
		internal static FieldElement Sub(ref FieldElement f, ref FieldElement g) => new FieldElement
		{
			X0 = f.X0 - g.X0,
			X1 = f.X1 - g.X1,
			X2 = f.X2 - g.X2,
			X3 = f.X3 - g.X3,
			X4 = f.X4 - g.X4,
			X5 = f.X5 - g.X5,
			X6 = f.X6 - g.X6,
			X7 = f.X7 - g.X7,
			X8 = f.X8 - g.X8,
			X9 = f.X9 - g.X9
		};
		
		
		/// <summary>
		/// h = f * 121666
		/// Can overlap h with f.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
		/// </summary>
		/// <param name="f"></param>
		/// <returns></returns>
		public static FieldElement Multiply121666(ref FieldElement f)
		{			
			var h0 = f.X0 * (long)121666;
			var h1 = f.X1 * (long)121666;
			var h2 = f.X2 * (long)121666;
			var h3 = f.X3 * (long)121666;
			var h4 = f.X4 * (long)121666;
			var h5 = f.X5 * (long)121666;
			var h6 = f.X6 * (long)121666;
			var h7 = f.X7 * (long)121666;
			var h8 = f.X8 * (long)121666;
			var h9 = f.X9 * (long)121666;
		
			var carry9 = (h9 + (1 << 24)) >> 25; 
			h0 += carry9 * 19; 
			h9 -= carry9 << 25;
			
			var carry1 = (h1 + (1 << 24)) >> 25; 
			h2 += carry1; 
			h1 -= carry1 << 25;
			
			var carry3 = (h3 + (1 << 24)) >> 25; 
			h4 += carry3; 
			h3 -= carry3 << 25;
			
			var carry5 = (h5 + (1 << 24)) >> 25; 
			h6 += carry5; 
			h5 -= carry5 << 25;
			
			var carry7 = (h7 + (1 << 24)) >> 25; 
			h8 += carry7; 
			h7 -= carry7 << 25;
            
			var carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;
			
			var carry2 = (h2 + (1 << 25)) >> 26; 
			h3 += carry2; 
			h2 -= carry2 << 26;
			
			var carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;
			
			var carry6 = (h6 + (1 << 25)) >> 26; 
			h7 += carry6; 
			h6 -= carry6 << 26;
			
			var carry8 = (h8 + (1 << 25)) >> 26; 
			h9 += carry8; 
			h8 -= carry8 << 26;

			return new FieldElement
			{
				X0 = (int)h0,
				X1 = (int)h1,
				X2 = (int)h2,
				X3 = (int)h3,
				X4 = (int)h4,
				X5 = (int)h5,
				X6 = (int)h6,
				X7 = (int)h7,
				X8 = (int)h8,
				X9 = (int)h9
			};
		}
		
		
		/// <summary>
		/// h = f * f
		/// Can overlap h with f.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
		/// </summary>
		/// <param name="f"></param>
		/// <returns></returns>
		internal static FieldElement Squared(ref FieldElement f)
		{		
			var h0 = f.X0 * (long)f.X0 + (2 * f.X1) * (long)(38 * f.X9) + (2 * f.X2) * (long)(19 * f.X8) + (2 * f.X3) * (long)(38 * f.X7) + (2 * f.X4) * (long)(19 * f.X6) + f.X5 * (long)(38 * f.X5);
			var h1 = (2 * f.X0) * (long)f.X1 + f.X2 * (long)(38 * f.X9) + (2 * f.X3) * (long)(19 * f.X8) + f.X4 * (long)(38 * f.X7) + (2 * f.X5) * (long)(19 * f.X6);
			var h2 = (2 * f.X0) * (long)f.X2 + (2 * f.X1) * (long)f.X1 + (2 * f.X3) * (long)(38 * f.X9) + (2 * f.X4) * (long)(19 * f.X8) + (2 * f.X5) * (long)(38 * f.X7) + f.X6 * (long)(19 * f.X6);
			var h3 = (2 * f.X0) * (long)f.X3 + (2 * f.X1) * (long)f.X2 + f.X4 * (long)(38 * f.X9) + (2 * f.X5) * (long)(19 * f.X8) + f.X6 * (long)(38 * f.X7);
			var h4 = (2 * f.X0) * (long)f.X4 + (2 * f.X1) * (long)(2 * f.X3) + f.X2 * (long)f.X2 + (2 * f.X5) * (long)(38 * f.X9) + (2 * f.X6) * (long)(19 * f.X8) + f.X7 * (long)(38 * f.X7);
			var h5 = (2 * f.X0) * (long)f.X5 + (2 * f.X1) * (long)f.X4 + (2 * f.X2) * (long)f.X3 + f.X6 * (long)(38 * f.X9) + (2 * f.X7) * (long)(19 * f.X8);
			var h6 = (2 * f.X0) * (long)f.X6 + (2 * f.X1) * (long)(2 * f.X5) + (2 * f.X2) * (long)f.X4 + (2 * f.X3) * (long)f.X3 + (2 * f.X7) * (long)(38 * f.X9) + f.X8 * (long)(19 * f.X8);
			var h7 = (2 * f.X0) * (long)f.X7 + (2 * f.X1) * (long)f.X6 + (2 * f.X2) * (long)f.X5 + (2 * f.X3) * (long)f.X4 + f.X8 * (long)(38 * f.X9);
			var h8 = (2 * f.X0) * (long)f.X8 + (2 * f.X1) * (long)(2 * f.X7) + (2 * f.X2) * (long)f.X6 + (2 * f.X3) * (long)(2 * f.X5) + f.X4 * (long)f.X4 + f.X9 * (long)(38 * f.X9);
			var h9 = (2 * f.X0) * (long)f.X9 + (2 * f.X1) * (long)f.X8 + (2 * f.X2) * (long)f.X7 + (2 * f.X3) * (long)f.X6 + (2 * f.X4) * (long)f.X5;	

			var carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;
			
			var carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;
			
			var carry1 = (h1 + (1 << 24)) >> 25; 
			h2 += carry1; 
			h1 -= carry1 << 25;
			
			var carry5 = (h5 + (1 << 24)) >> 25; 
			h6 += carry5; 
			h5 -= carry5 << 25;
			
			var carry2 = (h2 + (1 << 25)) >> 26; 
			h3 += carry2; 
			h2 -= carry2 << 26;
			
			var carry6 = (h6 + (1 << 25)) >> 26; 
			h7 += carry6; 
			h6 -= carry6 << 26;
			
			var carry3 = (h3 + (1 << 24)) >> 25; 
			h4 += carry3; 
			h3 -= carry3 << 25;
			
			var carry7 = (h7 + (1 << 24)) >> 25; 
			h8 += carry7; 
			h7 -= carry7 << 25;
			
			carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;
			
			var carry8 = (h8 + (1 << 25)) >> 26; 
			h9 += carry8; 
			h8 -= carry8 << 26;
			
			var carry9 = (h9 + (1 << 24)) >> 25; 
			h0 += carry9 * 19; 
			h9 -= carry9 << 25;
			
			carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;

			return new FieldElement
			{
				X0 = (int) h0,
				X1 = (int) h1,
				X2 = (int) h2,
				X3 = (int) h3,
				X4 = (int) h4,
				X5 = (int) h5,
				X6 = (int) h6,
				X7 = (int) h7,
				X8 = (int) h8,
				X9 = (int) h9
			};
		}
		
		
		/// <summary>
        /// Preconditions:
        /// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
        /// 
        /// Write p=2^255-19; q=floor(h/p).
        /// Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
        /// 
        /// Proof:
        /// Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
        /// Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
        /// 
        /// Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
        /// Then 0<y<1.
        /// 
        /// Write r=h-pq.
        /// Have 0<=r<=p-1=2^255-20.
        /// Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
        /// 
        /// Write x=r+19(2^-255)r+y.
        /// Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
        /// 
        /// Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
        /// so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
        /// </summary>
        /// <param name="s"></param>
        /// <param name="offset"></param>
        /// <param name="h"></param>
        internal static void ToBytes(byte[] s, int offset, ref FieldElement h)
        {            
            var hr = Reduce(ref h);
            /*
            Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
            Have h0+...+2^230 h9 between 0 and 2^255-1;
            evidently 2^255 h10-2^255 q = 0.
            Goal: Output h0+...+2^230 h9.
            */
            unchecked
            {
                s[offset + 0] = (byte) (hr.X0 >> 0);
                s[offset + 1] = (byte) (hr.X0 >> 8);
                s[offset + 2] = (byte) (hr.X0 >> 16);
                s[offset + 3] = (byte) ((hr.X0 >> 24) | (hr.X1 << 2));
                s[offset + 4] = (byte) (hr.X1 >> 6);
                s[offset + 5] = (byte) (hr.X1 >> 14);
                s[offset + 6] = (byte) ((hr.X1 >> 22) | (hr.X2 << 3));
                s[offset + 7] = (byte) (hr.X2 >> 5);
                s[offset + 8] = (byte) (hr.X2 >> 13);
                s[offset + 9] = (byte) ((hr.X2 >> 21) | (hr.X3 << 5));
                s[offset + 10] = (byte) (hr.X3 >> 3);
                s[offset + 11] = (byte) (hr.X3 >> 11);
                s[offset + 12] = (byte) ((hr.X3 >> 19) | (hr.X4 << 6));
                s[offset + 13] = (byte) (hr.X4 >> 2);
                s[offset + 14] = (byte) (hr.X4 >> 10);
                s[offset + 15] = (byte) (hr.X4 >> 18);
                s[offset + 16] = (byte) (hr.X5 >> 0);
                s[offset + 17] = (byte) (hr.X5 >> 8);
                s[offset + 18] = (byte) (hr.X5 >> 16);
                s[offset + 19] = (byte) ((hr.X5 >> 24) | (hr.X6 << 1));
                s[offset + 20] = (byte) (hr.X6 >> 7);
                s[offset + 21] = (byte) (hr.X6 >> 15);
                s[offset + 22] = (byte) ((hr.X6 >> 23) | (hr.X7 << 3));
                s[offset + 23] = (byte) (hr.X7 >> 5);
                s[offset + 24] = (byte) (hr.X7 >> 13);
                s[offset + 25] = (byte) ((hr.X7 >> 21) | (hr.X8 << 4));
                s[offset + 26] = (byte) (hr.X8 >> 4);
                s[offset + 27] = (byte) (hr.X8 >> 12);
                s[offset + 28] = (byte) ((hr.X8 >> 20) | (hr.X9 << 6));
                s[offset + 29] = (byte) (hr.X9 >> 2);
                s[offset + 30] = (byte) (hr.X9 >> 10);
                s[offset + 31] = (byte) (hr.X9 >> 18);
            }
        }

		
        private static FieldElement Reduce( ref FieldElement h)
        {
            var q = (19 * h.X9 + (1 << 24)) >> 25;
            q = (h.X0 + q) >> 26;
            q = (h.X1 + q) >> 25;
            q = (h.X2 + q) >> 26;
            q = (h.X3 + q) >> 25;
            q = (h.X4 + q) >> 26;
            q = (h.X5 + q) >> 25;
            q = (h.X6 + q) >> 26;
            q = (h.X7 + q) >> 25;
            q = (h.X8 + q) >> 26;
            q = (h.X9 + q) >> 25;

            /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
            h.X0 += 19 * q;
            /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
            var carry0 = h.X0 >> 26; 
            h.X1 += carry0; 
            h.X0 -= carry0 << 26;
            
            var carry1 = h.X1 >> 25; 
            h.X2 += carry1; 
            h.X1 -= carry1 << 25;
            
            var carry2 = h.X2 >> 26; 
            h.X3 += carry2; 
            h.X2 -= carry2 << 26;
            
            var carry3 = h.X3 >> 25; 
            h.X4 += carry3; 
            h.X3 -= carry3 << 25;
            
            var carry4 = h.X4 >> 26; 
            h.X5 += carry4; 
            h.X4 -= carry4 << 26;
            
            var carry5 = h.X5 >> 25; 
            h.X6 += carry5; 
            h.X5 -= carry5 << 25;
            
            var carry6 = h.X6 >> 26; 
            h.X7 += carry6; 
            h.X6 -= carry6 << 26;
            
            var carry7 = h.X7 >> 25; 
            h.X8 += carry7; 
            h.X7 -= carry7 << 25;
            
            var carry8 = h.X8 >> 26; 
            h.X9 += carry8; 
            h.X8 -= carry8 << 26;
            
            var carry9 = h.X9 >> 25; 
            h.X9 -= carry9 << 25;
            /* h10 = carry9 */

            return new FieldElement
            {
                X0 = h.X0,
                X1 = h.X1,
                X2 = h.X2,
                X3 = h.X3,
                X4 = h.X4,
                X5 = h.X5,
                X6 = h.X6,
                X7 = h.X7,
                X8 = h.X8,
                X9 = h.X9
            };
        }
		
		
		/// <summary>
		/// h = 2 * f * f
		/// Can overlap h with f.
		/// 
		/// Preconditions:
		/// |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
		/// 
		/// Postconditions:
		/// |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
		/// </summary>
		/// <param name="f"></param>
		internal static FieldElement DoubleSquare(ref FieldElement f)
		{
			var h0 = f.X0 * (long)f.X0 + (2 * f.X1) * (long)(38 * f.X9) + (2 * f.X2) * (long)(19 * f.X8) + (2 * f.X3) * (long)(38 * f.X7) + (2 * f.X4) * (long)(19 * f.X6) + f.X5 * (long)(38 * f.X5);
			var h1 = (2 * f.X0) * (long)f.X1 + f.X2 * (long)(38 * f.X9) + (2 * f.X3) * (long)(19 * f.X8) + f.X4 * (long)(38 * f.X7) + (2 * f.X5) * (long)(19 * f.X6);
			var h2 = (2 * f.X0) * (long)f.X2 + (2 * f.X1) * (long)f.X1 + (2 * f.X3) * (long)(38 * f.X9) + (2 * f.X4) * (long)(19 * f.X8) + (2 * f.X5) * (long)(38 * f.X7) + f.X6 * (long)(19 * f.X6);
			var h3 = (2 * f.X0) * (long)f.X3 + (2 * f.X1) * (long)f.X2 + f.X4 * (long)(38 * f.X9) + (2 * f.X5) * (long)(19 * f.X8) + f.X6 * (long)(38 * f.X7);
			var h4 = (2 * f.X0) * (long)f.X4 + (2 * f.X1) * (long)(2 * f.X3) + f.X2 * (long)f.X2 + (2 * f.X5) * (long)(38 * f.X9) + (2 * f.X6) * (long)(19 * f.X8) + f.X7 * (long)(38 * f.X7);
			var h5 = (2 * f.X0) * (long)f.X5 + (2 * f.X1) * (long)f.X4 + (2 * f.X2) * (long)f.X3 + f.X6 * (long)(38 * f.X9) + (2 * f.X7) * (long)(19 * f.X8);
			var h6 = (2 * f.X0) * (long)f.X6 + (2 * f.X1) * (long)(2 * f.X5) + (2 * f.X2) * (long)f.X4 + (2 * f.X3) * (long)f.X3 + (2 * f.X7) * (long)(38 * f.X9) + f.X8 * (long)(19 * f.X8);
			var h7 = (2 * f.X0) * (long)f.X7 + (2 * f.X1) * (long)f.X6 + (2 * f.X2) * (long)f.X5 + (2 * f.X3) * (long)f.X4 + f.X8 * (long)(38 * f.X9);
			var h8 = (2 * f.X0) * (long)f.X8 + (2 * f.X1) * (long)(2 * f.X7) + (2 * f.X2) * (long)f.X6 + (2 * f.X3) * (long)(2 * f.X5) + f.X4 * (long)f.X4 + f.X9 * (long)(38 * f.X9);
			var h9 = (2 * f.X0) * (long)f.X9 + (2 * f.X1) * (long)f.X8 + (2 * f.X2) * (long)f.X7 + (2 * f.X3) * (long)f.X6 + (2 * f.X4) * (long)f.X5;			

			h0 += h0;
			h1 += h1;
			h2 += h2;
			h3 += h3;
			h4 += h4;
			h5 += h5;
			h6 += h6;
			h7 += h7;
			h8 += h8;
			h9 += h9;

			var carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;
			
			var carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;

			var carry1 = (h1 + (1 << 24)) >> 25; 
			h2 += carry1; 
			h1 -= carry1 << 25;
			
			var carry5 = (h5 + (1 << 24)) >> 25; 
			h6 += carry5; 
			h5 -= carry5 << 25;

			var carry2 = (h2 + (1 << 25)) >> 26; 
			h3 += carry2; 
			h2 -= carry2 << 26;
			
			var carry6 = (h6 + (1 << 25)) >> 26; 
			h7 += carry6; 
			h6 -= carry6 << 26;

			var carry3 = (h3 + (1 << 24)) >> 25; 
			h4 += carry3; 
			h3 -= carry3 << 25;
			
			var carry7 = (h7 + (1 << 24)) >> 25; 
			h8 += carry7; 
			h7 -= carry7 << 25;

			carry4 = (h4 + (1 << 25)) >> 26; 
			h5 += carry4; 
			h4 -= carry4 << 26;
			
			var carry8 = (h8 + (1 << 25)) >> 26; 
			h9 += carry8; 
			h8 -= carry8 << 26;

			var carry9 = (h9 + (1 << 24)) >> 25; 
			h0 += carry9 * 19; 
			h9 -= carry9 << 25;

			carry0 = (h0 + (1 << 25)) >> 26; 
			h1 += carry0; 
			h0 -= carry0 << 26;

			return new FieldElement
			{
				X0 = (int)h0,
				X1 = (int)h1,
				X2 = (int)h2,
				X3 = (int)h3,
				X4 = (int)h4,
				X5 = (int)h5,
				X6 = (int)h6,
				X7 = (int)h7,
				X8 = (int)h8,
				X9 = (int)h9
			};
		}
	}
}