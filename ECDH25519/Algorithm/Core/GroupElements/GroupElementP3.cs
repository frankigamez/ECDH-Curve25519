namespace ECDH25519.Algorithm.Core.GroupElements
{
    /// <summary>
    /// Here the group is the set of pairs (x,y) of field elements (see fe.h)
    /// satisfying -x^2 + y^2 = 1 + d x^2y^2
    /// where d = -121665/121666.
    /// 
    /// Representations:
    /// 	(extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
    /// </summary>
    internal struct GroupElementP3
    {
        public FieldElement X;
        public FieldElement Y;
        public FieldElement Z;
        public FieldElement T;
    }
}