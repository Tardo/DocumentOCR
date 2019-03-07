/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.fragments;


import android.graphics.Bitmap;

import ocr.document.tardo.documentocr.utils.OCRInfo;

public class OCRTaskInfo {
    public Boolean mRunning;
    public OCRInfo mOCRInfo;
    public Bitmap mOCRImage;
    public String mOCRBoxes;

    OCRTaskInfo() {
        mRunning = false;
        mOCRInfo = null;
        mOCRImage = null;
    }
}