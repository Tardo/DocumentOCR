package icc;

import icc.tags.ICCCurveType;
import icc.tags.ICCXYZType;

public abstract class RestrictedICCProfile {
    protected static final int BLUE = 2;
    protected static final int GRAY = 0;
    protected static final int GREEN = 1;
    protected static final int RED = 0;
    protected static final String eol = System.getProperty("line.separator");
    public static final int kMonochromeInput = 0;
    public static final int kThreeCompInput = 1;
    public ICCXYZType[] colorant;
    public ICCCurveType[] trc;

    public abstract int getType();

    public static RestrictedICCProfile createInstance(ICCCurveType rcurve, ICCCurveType gcurve, ICCCurveType bcurve, ICCXYZType rcolorant, ICCXYZType gcolorant, ICCXYZType bcolorant) {
        return MatrixBasedRestrictedProfile.createInstance(rcurve, gcurve, bcurve, rcolorant, gcolorant, bcolorant);
    }

    public static RestrictedICCProfile createInstance(ICCCurveType gcurve) {
        return MonochromeInputRestrictedProfile.createInstance(gcurve);
    }

    protected RestrictedICCProfile(ICCCurveType gcurve) {
        this.trc = new ICCCurveType[1];
        this.colorant = null;
        this.trc[0] = gcurve;
    }

    protected RestrictedICCProfile(ICCCurveType rcurve, ICCCurveType gcurve, ICCCurveType bcurve, ICCXYZType rcolorant, ICCXYZType gcolorant, ICCXYZType bcolorant) {
        this.trc = new ICCCurveType[3];
        this.colorant = new ICCXYZType[3];
        this.trc[0] = rcurve;
        this.trc[1] = gcurve;
        this.trc[2] = bcurve;
        this.colorant[0] = rcolorant;
        this.colorant[1] = gcolorant;
        this.colorant[2] = bcolorant;
    }
}
