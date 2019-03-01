/* Image binarization - Otsu algorithm
 *
 * Author: Bostjan Cigan (http://zerocool.is-a-geek.net)
 * Port to Android: Alexandre Díaz
 */
package ocr.document.tardo.documentocr.utils;

import android.graphics.Bitmap;
import android.graphics.Color;


public class OtsuBinarize {

    private static Bitmap original, grayscale, binarized;

    public static Bitmap run(Bitmap inputImage) {
        original = inputImage;
        grayscale = toGray(original);
        binarized = binarize(grayscale);
        return binarized;
    }

    // Return histogram of grayscale image
    public static int[] imageHistogram(Bitmap input) {

        input.getPixel(1, 1);

        int[] histogram = new int[256];

        for(int i=0; i<histogram.length; i++) histogram[i] = 0;

        for(int i=0; i<input.getWidth(); i++) {
            for(int j=0; j<input.getHeight(); j++) {
                int red = Color.red(input.getPixel(i, j));
                histogram[red]++;
            }
        }

        return histogram;

    }

    // The luminance method
    private static Bitmap toGray(Bitmap original) {

        int alpha, red, green, blue;
        int newPixel;

        Bitmap lum = Bitmap.createBitmap(original, 0, 0, original.getWidth(), original.getHeight());

        for(int i=0; i<original.getWidth(); i++) {
            for(int j=0; j<original.getHeight(); j++) {

                // Get pixels by R, G, B
                int pixel = original.getPixel(i, j);
                alpha = Color.alpha(pixel);
                red = Color.red(pixel);
                green = Color.green(pixel);
                blue = Color.blue(pixel);

                red = (int) (0.21 * red + 0.71 * green + 0.07 * blue);
                // Return back to original format
                newPixel = colorToRGB(alpha, red, red, red);

                // Write pixels into image
                lum.setPixel(i, j, newPixel);

            }
        }

        return lum;

    }

    // Get binary treshold using Otsu's method
    private static int otsuTreshold(Bitmap original) {

        int[] histogram = imageHistogram(original);
        int total = original.getHeight() * original.getWidth();

        float sum = 0;
        for(int i=0; i<256; i++) sum += i * histogram[i];

        float sumB = 0;
        int wB = 0;
        int wF = 0;

        float varMax = 0;
        int threshold = 0;

        for(int i=0 ; i<256 ; i++) {
            wB += histogram[i];
            if(wB == 0) continue;
            wF = total - wB;

            if(wF == 0) break;

            sumB += (float) (i * histogram[i]);
            float mB = sumB / wB;
            float mF = (sum - sumB) / wF;

            float varBetween = (float) wB * (float) wF * (mB - mF) * (mB - mF);

            if(varBetween > varMax) {
                varMax = varBetween;
                threshold = i;
            }
        }

        return threshold;

    }

    private static Bitmap binarize(Bitmap original) {

        int red;
        int newPixel;

        int threshold = otsuTreshold(original);

        Bitmap binarized = Bitmap.createBitmap(original, 0, 0, original.getWidth(), original.getHeight());

        for(int i=0; i<original.getWidth(); i++) {
            for(int j=0; j<original.getHeight(); j++) {

                // Get pixels
                final int pixel = original.getPixel(i, j);
                red = Color.red(pixel);
                int alpha = Color.alpha(pixel);
                if(red > threshold) {
                    newPixel = 255;
                }
                else {
                    newPixel = 0;
                }
                newPixel = colorToRGB(alpha, newPixel, newPixel, newPixel);
                binarized.setPixel(i, j, newPixel);

            }
        }

        return binarized;

    }

    // Convert R, G, B, Alpha to standard 8 bit
    private static int colorToRGB(int alpha, int red, int green, int blue) {

        int newPixel = 0;
        newPixel += alpha;
        newPixel = newPixel << 8;
        newPixel += red; newPixel = newPixel << 8;
        newPixel += green; newPixel = newPixel << 8;
        newPixel += blue;

        return newPixel;

    }

}
