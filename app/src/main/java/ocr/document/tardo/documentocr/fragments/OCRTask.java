/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.fragments;

import java.util.Date;

public class OCRTask {
    public static final int ID_TYPE_ELECTRONIC = 1;
    public static final int ID_TYPE_TRADITIONAL = 2;
    public static final int ID_TYPE_PASSPORT = 3;

    public Boolean mState;
    public String mResult;
    public Boolean mRunning;

    public String mName;
    public String mDNI;
    public Date mBirthdayDate;
    public String mCardNumber;
    public Date mEndDate;
    public String mNation;
    public String mSex;
    public int mIDType;

    OCRTask() {
        mState = false;
        mRunning = false;
        mIDType = ID_TYPE_ELECTRONIC;
    }
}