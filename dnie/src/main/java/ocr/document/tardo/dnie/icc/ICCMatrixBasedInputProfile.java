package icc;

import colorspace.ColorSpace;
import colorspace.ColorSpaceException;

public class ICCMatrixBasedInputProfile extends ICCProfile {
    public static ICCMatrixBasedInputProfile createInstance(ColorSpace csm) throws ColorSpaceException, ICCProfileInvalidException {
        return new ICCMatrixBasedInputProfile(csm);
    }

    protected ICCMatrixBasedInputProfile(ColorSpace csm) throws ColorSpaceException, ICCProfileInvalidException {
        super(csm);
    }
}
