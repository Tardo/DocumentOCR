/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.utils;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.util.Log;

import com.googlecode.tesseract.android.TessBaseAPI;


public class Bitmap2Text {

    public static Bitmap mCroppedImage;
    public static String mBoxes;

    public static String run(Bitmap bitmap, Rect cropArea, TessBaseAPI tessApi) {
        float centerW = bitmap.getWidth()/2 - cropArea.width()/2;
        float centerH = bitmap.getHeight()/2 - cropArea.height()/2;
        int cropX = (int)(centerW);
        int cropY = (int)(centerH);

        // Crop & Binarize input image
        mCroppedImage = Bitmap.createBitmap(
                bitmap,
                cropX,
                cropY,
                cropArea.width(),
                cropArea.height());

        Bitmap binarizedImage = OtsuBinarize.run(mCroppedImage);

        // Run Tesseract
        tessApi.setImage(binarizedImage);

        mBoxes = tessApi.getBoxText(0);

        return tessApi.getUTF8Text();
    }

}