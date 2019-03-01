package icc;

import icc.tags.ICCCurveType;

public class MonochromeInputRestrictedProfile extends RestrictedICCProfile {
    public static RestrictedICCProfile createInstance(ICCCurveType c) {
        return new MonochromeInputRestrictedProfile(c);
    }

    private MonochromeInputRestrictedProfile(ICCCurveType c) {
        super(c);
    }

    public int getType() {
        return 0;
    }

    public String toString() {
        StringBuffer rep = new StringBuffer("Monochrome Input Restricted ICC profile" + eol);
        rep.append("trc[GRAY]:" + eol).append(this.trc[0]).append(eol);
        return rep.toString();
    }
}
