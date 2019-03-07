/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.fragments;

import android.graphics.Bitmap;
import android.graphics.Rect;

import com.googlecode.tesseract.android.TessBaseAPI;

import ocr.document.tardo.documentocr.utils.Bitmap2Text;
import ocr.document.tardo.documentocr.utils.OCRBParser;


public class OCRTask implements Runnable {

    private final Bitmap mBitmap;
    private final Rect mCropArea;
    private final TessBaseAPI mTessApi;
    private OCRTaskInfo mOCRTaskInfo;


    public OCRTask(Bitmap bitmap, Rect cropArea, TessBaseAPI tessApi, OCRTaskInfo ocrTaskInfo) {
        mBitmap = bitmap;
        mCropArea = cropArea;
        mTessApi = tessApi;
        mOCRTaskInfo = ocrTaskInfo;
    }


    @Override
    public void run() {
        final String recognizedText = Bitmap2Text.run(mBitmap, mCropArea, mTessApi);
        mOCRTaskInfo.mOCRInfo = OCRBParser.run(recognizedText);
        mOCRTaskInfo.mOCRImage = Bitmap2Text.mCroppedImage;
        mOCRTaskInfo.mOCRBoxes = Bitmap2Text.mBoxes;
        mOCRTaskInfo.mRunning = false;
    }

}