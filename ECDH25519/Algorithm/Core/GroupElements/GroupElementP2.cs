namespace ECDH25519.Algorithm.Core.GroupElements
{
    /// <summary>
    /// Here the group is the set of pairs (x,y) of field elements
    /// satisfying -x^2 + y^2 = 1 + d x^2y^2
    /// where d = -121665/121666.
    /// 
    /// Representations:
    /// 	(projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
    /// </summary>
    internal struct GroupElementP2
    {
        public FieldElement X;
        public FieldElement Y;
        public FieldElement Z;
    }
}