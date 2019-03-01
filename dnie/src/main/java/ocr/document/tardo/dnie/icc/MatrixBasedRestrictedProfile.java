package icc;

import icc.tags.ICCCurveType;
import icc.tags.ICCXYZType;

public class MatrixBasedRestrictedProfile extends RestrictedICCProfile {
    public static RestrictedICCProfile createInstance(ICCCurveType rcurve, ICCCurveType gcurve, ICCCurveType bcurve, ICCXYZType rcolorant, ICCXYZType gcolorant, ICCXYZType bcolorant) {
        return new MatrixBasedRestrictedProfile(rcurve, gcurve, bcurve, rcolorant, gcolorant, bcolorant);
    }

    protected MatrixBasedRestrictedProfile(ICCCurveType rcurve, ICCCurveType gcurve, ICCCurveType bcurve, ICCXYZType rcolorant, ICCXYZType gcolorant, ICCXYZType bcolorant) {
        super(rcurve, gcurve, bcurve, rcolorant, gcolorant, bcolorant);
    }

    public int getType() {
        return 1;
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("[Matrix-Based Input Restricted ICC profile").append(eol);
        rep.append("trc[RED]:").append(eol).append(this.trc[0]).append(eol);
        rep.append("trc[RED]:").append(eol).append(this.trc[1]).append(eol);
        rep.append("trc[RED]:").append(eol).append(this.trc[2]).append(eol);
        rep.append("Red colorant:  ").append(this.colorant[0]).append(eol);
        rep.append("Red colorant:  ").append(this.colorant[1]).append(eol);
        rep.append("Red colorant:  ").append(this.colorant[2]).append(eol);
        return rep.append("]").toString();
    }
}
