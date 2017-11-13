using System;
using System.Runtime.CompilerServices;

namespace ECDH25519.Algorithm.Core.Operations
{
	internal static class MontgomeryOperations
	{
		public static byte[] ScalarMultiply(byte[] n, byte[] p, int qSize)
		{
			var q = new byte[qSize];
			var qSegment = new ArraySegment<byte>(q);
			var nSegment = new ArraySegment<byte>(n);
			var pSegment = new ArraySegment<byte>(p);
			
			var p0 = FieldElementOperations.FromBytes(pSegment.Array, pSegment.Offset);
			var q0 = Calculate(nSegment.Array, nSegment.Offset, ref p0);
			FieldElementOperations.ToBytes(qSegment.Array, qSegment.Offset, ref q0);
			
			return q;
		}
		
		public static void Clamp(byte[] s, int offset)
		{
			s[offset + 0] &= 248;
			s[offset + 31] &= 127;
			s[offset + 31] |= 64;
		}

		private static FieldElement Calculate(byte[] n, int noffset, ref FieldElement p)
		{
			var e = new byte[32];
			uint i;
			FieldElement x1;
			FieldElement x2;
			FieldElement z2;
			FieldElement x3;
			FieldElement z3;
			int pos;
			uint swap;

			for (i = 0; i < 32; ++i)
				e[i] = n[noffset + i];
		    Clamp(e, 0);
			x1 = p;
			x2 = FieldElementOperations.Set1();
			z2 = FieldElementOperations.Set0();
			x3 = x1;
			z3 = FieldElementOperations.Set1();

			swap = 0;
			for (pos = 254; pos >= 0; --pos)
			{
				var b = (uint)(e[pos / 8] >> (pos & 7));
				b &= 1;
				swap ^= b;
				FieldElementOperations.Cswap(ref x2, ref x3, swap);
				FieldElementOperations.Cswap(ref z2, ref z3, swap);
				swap = b;
				
				/* D = X3-Z3 */
				/* asm 1: fe_sub(>D=fe#5,<X3=fe#3,<Z3=fe#4); */
				/* asm 2: fe_sub(>D=tmp0,<X3=x3,<Z3=z3); */
				var tmp0 = FieldElementOperations.Sub(ref  x3, ref  z3);

				/* B = X2-Z2 */
				/* asm 1: fe_sub(>B=fe#6,<X2=fe#1,<Z2=fe#2); */
				/* asm 2: fe_sub(>B=tmp1,<X2=x2,<Z2=z2); */
				var tmp1 = FieldElementOperations.Sub(ref x2, ref z2);

				/* A = X2+Z2 */
				/* asm 1: fe_add(>A=fe#1,<X2=fe#1,<Z2=fe#2); */
				/* asm 2: fe_add(>A=x2,<X2=x2,<Z2=z2); */
				x2 = FieldElementOperations.Add(ref x2, ref z2);

				/* C = X3+Z3 */
				/* asm 1: fe_add(>C=fe#2,<X3=fe#3,<Z3=fe#4); */
				/* asm 2: fe_add(>C=z2,<X3=x3,<Z3=z3); */
				z2 = FieldElementOperations.Add(ref  x3, ref z3);

				/* DA = D*A */
				/* asm 1: fe_mul(>DA=fe#4,<D=fe#5,<A=fe#1); */
				/* asm 2: fe_mul(>DA=z3,<D=tmp0,<A=x2); */
				z3 = FieldElementOperations.Multiply(ref tmp0, ref x2);

				/* CB = C*B */
				/* asm 1: fe_mul(>CB=fe#2,<C=fe#2,<B=fe#6); */
				/* asm 2: fe_mul(>CB=z2,<C=z2,<B=tmp1); */
				z2 = FieldElementOperations.Multiply(ref  z2, ref tmp1);

				/* BB = B^2 */
				/* asm 1: fe_sq(>BB=fe#5,<B=fe#6); */
				/* asm 2: fe_sq(>BB=tmp0,<B=tmp1); */
				tmp0 = FieldElementOperations.Squared(ref  tmp1);

				/* AA = A^2 */
				/* asm 1: fe_sq(>AA=fe#6,<A=fe#1); */
				/* asm 2: fe_sq(>AA=tmp1,<A=x2); */
				tmp1 = FieldElementOperations.Squared(ref  x2);

				/* t0 = DA+CB */
				/* asm 1: fe_add(>t0=fe#3,<DA=fe#4,<CB=fe#2); */
				/* asm 2: fe_add(>t0=x3,<DA=z3,<CB=z2); */
				x3 = FieldElementOperations.Add(ref z3, ref  z2);

				/* assign x3 to t0 */

				/* t1 = DA-CB */
				/* asm 1: fe_sub(>t1=fe#2,<DA=fe#4,<CB=fe#2); */
				/* asm 2: fe_sub(>t1=z2,<DA=z3,<CB=z2); */
				z2 = FieldElementOperations.Sub(ref z3, ref  z2);

				/* X4 = AA*BB */
				/* asm 1: fe_mul(>X4=fe#1,<AA=fe#6,<BB=fe#5); */
				/* asm 2: fe_mul(>X4=x2,<AA=tmp1,<BB=tmp0); */
				x2 = FieldElementOperations.Multiply(ref tmp1, ref  tmp0);

				/* E = AA-BB */
				/* asm 1: fe_sub(>E=fe#6,<AA=fe#6,<BB=fe#5); */
				/* asm 2: fe_sub(>E=tmp1,<AA=tmp1,<BB=tmp0); */
				tmp1 = FieldElementOperations.Sub(ref  tmp1, ref tmp0);

				/* t2 = t1^2 */
				/* asm 1: fe_sq(>t2=fe#2,<t1=fe#2); */
				/* asm 2: fe_sq(>t2=z2,<t1=z2); */
				z2 = FieldElementOperations.Squared(ref z2);

				/* t3 = a24*E */
				/* asm 1: fe_mul121666(>t3=fe#4,<E=fe#6); */
				/* asm 2: fe_mul121666(>t3=z3,<E=tmp1); */
				z3 = FieldElementOperations.Multiply121666(ref tmp1);

				/* X5 = t0^2 */
				/* asm 1: fe_sq(>X5=fe#3,<t0=fe#3); */
				/* asm 2: fe_sq(>X5=x3,<t0=x3); */
				x3 = FieldElementOperations.Squared(ref  x3);

				/* t4 = BB+t3 */
				/* asm 1: fe_add(>t4=fe#5,<BB=fe#5,<t3=fe#4); */
				/* asm 2: fe_add(>t4=tmp0,<BB=tmp0,<t3=z3); */
				tmp0 = FieldElementOperations.Add(ref  tmp0, ref z3);

				/* Z5 = X1*t2 */
				/* asm 1: fe_mul(>Z5=fe#4,x1,<t2=fe#2); */
				/* asm 2: fe_mul(>Z5=z3,x1,<t2=z2); */
				z3 = FieldElementOperations.Multiply(ref x1, ref  z2);

				/* Z4 = E*t4 */
				/* asm 1: fe_mul(>Z4=fe#2,<E=fe#6,<t4=fe#5); */
				/* asm 2: fe_mul(>Z4=z2,<E=tmp1,<t4=tmp0); */
				z2 = FieldElementOperations.Multiply(ref  tmp1, ref  tmp0);
			}
			
			FieldElementOperations.Cswap(ref x2, ref x3, swap);
			FieldElementOperations.Cswap(ref z2, ref z3, swap);
			z2 = FieldElementOperations.Invert(ref z2);
			x2 = FieldElementOperations.Multiply(ref x2, ref z2);
			var q = x2;
			Wipe(e);
			return q;
		}

		private static void Wipe(byte[] data) => data?.InternalWipe(0, data.Length);

		[MethodImpl(MethodImplOptions.NoInlining)]
		private static void InternalWipe(this byte[] data, int offset, int count) => Array.Clear(data, offset, count);
	}
}