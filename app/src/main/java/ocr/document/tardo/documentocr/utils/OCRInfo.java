/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.utils;

import java.util.Date;

public class OCRInfo {
    public static final int ID_TYPE_ELECTRONIC = 1;
    public static final int ID_TYPE_TRADITIONAL = 2;
    public static final int ID_TYPE_PASSPORT = 3;

    public String mRaw;

    public String mName;
    public String mDNI;
    public Date mBirthdayDate;
    public String mCardNumber;
    public Date mEndDate;
    public String mCountry;
    public String mGender;
    public int mIDType;

    OCRInfo() {
        mIDType = ID_TYPE_ELECTRONIC;
    }
}
