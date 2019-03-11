/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.utils;

import android.graphics.Bitmap;
import android.graphics.Rect;

import com.googlecode.tesseract.android.TessBaseAPI;


public class Bitmap2Text {

    public static Bitmap mCroppedImage;
    public static String mBoxes;

    public static String run(Bitmap bitmap, Rect cropArea, TessBaseAPI tessApi) {
        // Crop & Binarize input image
        mCroppedImage = Bitmap.createBitmap(
                bitmap,
                cropArea.left,
                cropArea.top,
                cropArea.width(),
                cropArea.height());

        // Run Tesseract
        tessApi.setImage(mCroppedImage);
        mBoxes = tessApi.getBoxText(0);
        return tessApi.getUTF8Text();
    }

}