namespace ECDH25519.Algorithm.Core.GroupElements
{
	/// <summary>
	/// Here the group is the set of pairs (x,y) of field elements (see fe.h)
	/// satisfying -x^2 + y^2 = 1 + d x^2y^2
	/// where d = -121665/121666.
	/// 
	/// Representations:
	/// 	(Duif): (y+x,y-x,2dxy)
	/// </summary>
	internal struct GroupElementPreComp
	{
		public FieldElement yplusx;
		public FieldElement yminusx;
		public FieldElement xy2d;

		public GroupElementPreComp(FieldElement yplusx, FieldElement yminusx, FieldElement xy2d)
		{
			this.yplusx = yplusx;
			this.yminusx = yminusx;
			this.xy2d = xy2d;
		}
	}
}
