package icc;

import colorspace.ColorSpace;
import colorspace.ColorSpaceException;

public class ICCMonochromeInputProfile extends ICCProfile {
    public static ICCMonochromeInputProfile createInstance(ColorSpace csm) throws ColorSpaceException, ICCProfileInvalidException {
        return new ICCMonochromeInputProfile(csm);
    }

    protected ICCMonochromeInputProfile(ColorSpace csm) throws ColorSpaceException, ICCProfileInvalidException {
        super(csm);
    }
}
