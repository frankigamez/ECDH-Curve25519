using System;

namespace ECDH25519.Algorithm.Core.Operations
{
	internal static class MontgomeryOperations
	{
		/// <summary>
		/// Curve25519 uses a so-called differential-addition chain proposed by Montgomery to multiply a point, 
		/// identified only by its x-coordinate, by a scalar
		/// </summary>
		/// <param name="n"></param>
		/// <param name="p"></param>
		/// <param name="qSize"></param>
		/// <returns></returns>
		internal static byte[] ScalarMultiplication(byte[] n, byte[] p, int qSize)
		{
			var q = new byte[qSize];			
			var p0 = FieldElementOperations.FromBytes(p);
			var q0 = CalculateLadderStep(n, ref p0);
			FieldElementOperations.ToBytes(q, ref q0);
			
			return q;
		}
		
		private static FieldElement CalculateLadderStep(byte[] n, ref FieldElement p, int noffset = 0)
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
			ClampOperation.Clamp(e, 0);
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
				FieldElementOperations.Swap(ref x2, ref x3, swap);
				FieldElementOperations.Swap(ref z2, ref z3, swap);
				swap = b;
				
				/* D = X3-Z3 */
				var tmp0 = FieldElementOperations.Sub(ref  x3, ref  z3);

				/* B = X2-Z2 */
				var tmp1 = FieldElementOperations.Sub(ref x2, ref z2);

				/* A = X2+Z2 */
				x2 = FieldElementOperations.Add(ref x2, ref z2);

				/* C = X3+Z3 */
				z2 = FieldElementOperations.Add(ref  x3, ref z3);

				/* DA = D*A */
				z3 = FieldElementOperations.Multiplication(ref tmp0, ref x2);

				/* CB = C*B */
				z2 = FieldElementOperations.Multiplication(ref  z2, ref tmp1);

				/* BB = B^2 */
				tmp0 = FieldElementOperations.Squared(ref  tmp1);

				/* AA = A^2 */
				tmp1 = FieldElementOperations.Squared(ref  x2);

				/* t0 = DA+CB */				
				x3 = FieldElementOperations.Add(ref z3, ref  z2);

				/* t1 = DA-CB */
				z2 = FieldElementOperations.Sub(ref z3, ref  z2);

				/* X4 = AA*BB */
				x2 = FieldElementOperations.Multiplication(ref tmp1, ref  tmp0);

				/* E = AA-BB */
				tmp1 = FieldElementOperations.Sub(ref  tmp1, ref tmp0);

				/* t2 = t1^2 */
				z2 = FieldElementOperations.Squared(ref z2);

				/* t3 = a24*E */
				z3 = FieldElementOperations.Multiply121666(ref tmp1);

				/* X5 = t0^2 */
				x3 = FieldElementOperations.Squared(ref  x3);

				/* t4 = BB+t3 */
				tmp0 = FieldElementOperations.Add(ref  tmp0, ref z3);

				/* Z5 = X1*t2 */
				z3 = FieldElementOperations.Multiplication(ref x1, ref  z2);

				/* Z4 = E*t4 */
				z2 = FieldElementOperations.Multiplication(ref  tmp1, ref  tmp0);
			}
			
			FieldElementOperations.Swap(ref x2, ref x3, swap);
			FieldElementOperations.Swap(ref z2, ref z3, swap);
			z2 = FieldElementOperations.Invert(ref z2);
			x2 = FieldElementOperations.Multiplication(ref x2, ref z2);
			var q = x2;
			Array.Clear(e, 0, e.Length);
			return q;
		}
	}
}