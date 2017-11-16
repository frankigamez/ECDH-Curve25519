namespace ECDH25519.Algorithm.Core.GroupElements
{
	/// <summary>
	/// Here the group is the set of pairs (x,y) of field elements
	/// satisfying -x^2 + y^2 = 1 + d x^2y^2
	/// where d = -121665/121666.
	/// 
	/// Representations:
	/// 	(Duif): (y+x,y-x,2dxy)
	/// </summary>
	internal struct GroupElementP4
	{
		public FieldElement YplusX;
		public FieldElement YminusX;
		public FieldElement XY2D;

		public GroupElementP4(FieldElement yplusX, FieldElement yminusX, FieldElement xy2d)
		{
			this.YplusX = yplusX;
			this.YminusX = yminusX;
			this.XY2D = xy2d;
		}
	}
}
