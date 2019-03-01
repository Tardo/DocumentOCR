/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.fragments;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.util.Log;

import com.googlecode.tesseract.android.TessBaseAPI;

import java.io.File;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.utils.OtsuBinarize;


public class Bitmap2Text implements Runnable {

    private static final String TAG = "Bitmap2Text";

    private final Bitmap mBitmap;
    private final Rect mCropArea;
    private final File mFile;
    private OCRBReaderFragment mFragment;
    private OCRTask mOCRTask;

    private Map<String, int[][]> mDNINewIndices;
    private Map<String, int[][]> mDNIOldIndices;


    Bitmap2Text(Bitmap bitmap, Rect cropArea, File file, OCRBReaderFragment fragment, OCRTask ocrTask) {
        mBitmap = bitmap;
        mCropArea = cropArea;
        mFile = file;
        mFragment = fragment;
        mOCRTask = ocrTask;
    }

    private int checkDigits(String toVerify) {
        final int[] m = new int[]{7, 3, 1};
        int i, n;

        for (i = n = 0; i < toVerify.length(); i++)
            if (Character.isDigit(toVerify.charAt(i)))
                n += (toVerify.charAt(i) - '0') * m[i % 3];
            else if (Character.isLetter(toVerify.charAt(i)))
                n += (Character.toUpperCase(toVerify.charAt(i)) - 'A') * m[i % 3];
            else
                return -1;
        return n % 10;
    }

    private String getNifNieLetter(String nif) {
        //Extraer letra del NIF
        final String letras = "TRWAGMYFPDXBNJZSQVHLCKE";
        final int dni = Integer.parseInt(nif) % 23;
        return letras.substring(dni, dni + 1);
    }

    private boolean isNifNie(String nif) {
        //si es NIE, eliminar la x,y,z inicial para tratarlo como nif
        if (nif.toUpperCase().startsWith("X") || nif.toUpperCase().startsWith("Y") || nif.toUpperCase().startsWith("Z"))
            nif = nif.substring(1);

        final Pattern nifPattern = Pattern.compile("(\\d{1,8})([TRWAGMYFPDXBNJZSQVHLCKEtrwagmyfpdxbnjzsqvhlcke])");
        final Matcher m = nifPattern.matcher(nif);
        if (m.matches())
            return getNifNieLetter(m.group(1)).equalsIgnoreCase(m.group(2));
        else
            return false;
    }


    @Override
    public void run() {
        float centerW = mBitmap.getWidth()/2 - mCropArea.width()/2;
        float centerH = mBitmap.getHeight()/2 - mCropArea.height()/2;
        int cropX = (int)(centerW);
        int cropY = (int)(centerH);

        Bitmap croppedImage = Bitmap.createBitmap(
                mBitmap,
                cropX,
                cropY,
                (int)mCropArea.width(),
                (int)mCropArea.height());

        Bitmap binarizedImage = OtsuBinarize.run(croppedImage);


        final TessBaseAPI tessApi = ((AppMain)mFragment.getActivity().getApplication()).getTessApi();
        tessApi.setImage(binarizedImage);

        final String recognizedText = tessApi.getUTF8Text();
        Log.d(TAG, "Readed:\n" + recognizedText);

        // Possible Values
        ArrayList<String> possibleSexValues = new ArrayList<String>();
        possibleSexValues.add("F");
        possibleSexValues.add("M");
        possibleSexValues.add("<");

        // PARSE OCR-B Data
        String[] lines = recognizedText.split(System.getProperty("line.separator"));
        try {
            if ('<' != lines[0].charAt(lines[0].length() - 7)) {
                // DNIe
                final int[][] zones = new int[][]{
                        {0, 2},     // Tipo
                        {2, 5},     // Nacion
                        {5, 14},    // Numero de Serie Tarjeta
                        {14, 15},   // Digito Control: Numero de Serie Tarjeta
                        {15, 24},   // Numero DNI

                        {0, 6},     // Fecha Nacimiento
                        {6, 7},     // Digito Control: Fecha Nacimiento
                        {7, 8},     // Sexo (M/F)
                        {8, 14},    // Fecha Caducidad
                        {14, 15},   // Digito Control: Fecha Caducidad
                        {15, 18},   // Nacionalidad
                        {29, 30},   // Digito Control Maestro

                        {0, 30},    // Nombre
                };

                String zoneCardNumber = lines[0].substring(zones[2][0], zones[2][1]);
                String zoneCardNumberVer = lines[0].substring(zones[3][0], zones[3][1]);
                String zoneDNI = lines[0].substring(zones[4][0], zones[4][1]);
                String zoneBirthDate = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneBirthDateVer = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneSex = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneOutDate = lines[1].substring(zones[8][0], zones[8][1]);
                String zoneOutDateVer = lines[1].substring(zones[9][0], zones[9][1]);
                String zoneNation = lines[1].substring(zones[10][0], zones[10][1]);
                String zoneName = lines[2].substring(zones[12][0], zones[12][1]);

                //Basic Info
                final Boolean DNIReaded = isNifNie(zoneDNI);

                // Verify Card Number
                int verificationCode = checkDigits(zoneCardNumber);
                int verCode = Integer.parseInt(zoneCardNumberVer);
                final Boolean CardNumberReaded = (verificationCode == verCode);

                // Verify BirthDate
                verificationCode = checkDigits(zoneBirthDate);
                verCode = Integer.parseInt(zoneBirthDateVer);
                final Boolean DateBirthReaded = (verificationCode == verCode);

                // Verify OutDate
                verificationCode = checkDigits(zoneOutDate);
                verCode = Integer.parseInt(zoneOutDateVer);
                final Boolean OutDateReaded = (verificationCode == verCode);

                // Verify Sex
                final Boolean SexReaded = possibleSexValues.contains(zoneSex);

                // Verify Master
                String toVerify = zoneCardNumber + zoneCardNumberVer + zoneDNI + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer;
                verificationCode = checkDigits(toVerify);
                verCode = Integer.parseInt(lines[1].substring(zones[11][0], zones[11][1]));
                final Boolean MasterVerificationReaded = (verificationCode == verCode);

                final Boolean allOk = (CardNumberReaded && DateBirthReaded && OutDateReaded && MasterVerificationReaded && DNIReaded && SexReaded);
                if (allOk) {
                    mOCRTask.mResult = recognizedText;
                    mOCRTask.mState = true;
                    mOCRTask.mName = zoneName.replaceAll("<", " ");
                    mOCRTask.mDNI = zoneDNI;
                    mOCRTask.mCardNumber = zoneCardNumber;
                    mOCRTask.mNation = zoneNation;
                    mOCRTask.mSex = zoneSex;

                    DateFormat df = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    mOCRTask.mBirthdayDate = df.parse(zoneBirthDate);
                    mOCRTask.mEndDate = df.parse(zoneOutDate);
                }

                Log.d(TAG, "Verification Code: " + verificationCode + " >> " + verCode);
            } else if (lines.length >= 3) {
                // DNI Traditional
                final int[][] zones = new int[][]{
                        {0, 2},     // Tipo
                        {2, 5},     // Nacion
                        {5, 14},   // Numero DNI
                        {14, 15},   // Digito Control: Numero DNI

                        {0, 6},     // Fecha Nacimiento
                        {6, 7},     // Digito Control: Fecha Nacimiento
                        {7, 8},     // Sexo (M/F)
                        {8, 14},    // Fecha Caducidad
                        {14, 15},   // Digito Control: Fecha Caducidad
                        {15, 18},   // Nacionalidad
                        {29, 30},   // Digito Control Maestro

                        {0, 30},    // Nombre
                };

                String zoneDNI = lines[0].substring(zones[2][0], zones[2][1]);
                String zoneDNIVer = lines[0].substring(zones[3][0], zones[3][1]);
                String zoneBirthDate = lines[1].substring(zones[4][0], zones[4][1]);
                String zoneBirthDateVer = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneSex = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneOutDate = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneOutDateVer = lines[1].substring(zones[8][0], zones[8][1]);
                String zoneNation = lines[1].substring(zones[9][0], zones[9][1]);
                String zoneName = lines[2].substring(zones[11][0], zones[11][1]);

                //Basic Info
                int verificationCode = checkDigits(zoneDNI);
                int verCode = Integer.parseInt(zoneDNIVer);
                final Boolean DNIReaded = (verificationCode == verCode) && isNifNie(zoneDNI);

                // Verify BirthDate
                verificationCode = checkDigits(zoneBirthDate);
                verCode = Integer.parseInt(zoneBirthDateVer);
                final Boolean DateBirthReaded = (verificationCode == verCode);

                // Verify OutDate
                verificationCode = checkDigits(zoneOutDate);
                verCode = Integer.parseInt(zoneOutDateVer);
                final Boolean OutDateReaded = (verificationCode == verCode);

                // Verify Sex
                final Boolean SexReaded = possibleSexValues.contains(zoneSex);

                // Verify Master
                String toVerify = zoneDNI + zoneDNIVer + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer;
                verificationCode = checkDigits(toVerify);
                verCode = Integer.parseInt(lines[1].substring(zones[10][0], zones[10][1]));
                final Boolean MasterVerificationReaded = (verificationCode == verCode);

                final Boolean allOk = (DNIReaded && DateBirthReaded && OutDateReaded && MasterVerificationReaded && SexReaded);
                if (allOk) {
                    mOCRTask.mResult = recognizedText;
                    mOCRTask.mState = true;
                    mOCRTask.mIDType = OCRTask.ID_TYPE_TRADITIONAL;
                    mOCRTask.mName = zoneName.replaceAll("<", " ");
                    mOCRTask.mDNI = zoneDNI;
                    mOCRTask.mNation = zoneNation;
                    mOCRTask.mSex = zoneSex;

                    DateFormat dfB = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    mOCRTask.mBirthdayDate = dfB.parse(zoneBirthDate);
                    DateFormat dfE = new SimpleDateFormat("ddMMyy", Locale.ENGLISH);
                    mOCRTask.mEndDate = dfE.parse(zoneOutDate);
                }

                Log.d(TAG, "Verification Code: " + verificationCode + " >> " + verCode);
            } else {
                // Pasaporte Electronico
                final int[][] zones = new int[][]{
                        {0, 1},     // Tipo
                        {2, 5},     // Nacion
                        {5, 43},    // Nombre

                        {0, 9},     // Num. Pasaporte
                        {9, 10},    // Digito Control: Num. Pasaporte
                        {10, 13},   // Nacionalidad
                        {13, 19},   // Fecha Nacimiento
                        {19, 20},   // Digito Control: Fecha Nacimiento
                        {20, 21},   // Sexo
                        {21, 27},   // Fecha Cadudidad
                        {27, 28},   // Digito Control: Fecha Caducidad
                        {28, 39},   // DNI Pasaporte
                        {42, 43},   // Digito Control: DNI
                        {43, 44},   // Digito Control Maestro
                };

                String zoneName = lines[0].substring(zones[2][0], zones[2][1]);
                String zonePassportNum = lines[1].substring(zones[3][0], zones[3][1]);
                String zonePassportNumVer = lines[1].substring(zones[4][0], zones[4][1]);
                String zoneNation = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneBirthDate = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneBirthDateVer = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneSex = lines[1].substring(zones[8][0], zones[8][1]);
                String zoneOutDate = lines[1].substring(zones[9][0], zones[9][1]);
                String zoneOutDateVer = lines[1].substring(zones[10][0], zones[10][1]);
                String zoneDNI = lines[1].substring(zones[11][0], zones[11][1]);
                String zoneDNIVer = lines[1].substring(zones[12][0], zones[12][1]);
                String zoneMasterVer = lines[1].substring(zones[13][0], zones[13][1]);


                // Verify Passport
                int verificationCode = checkDigits(zonePassportNum);
                int verCode = Integer.parseInt(zonePassportNumVer);
                final Boolean PassportReaded = (verificationCode == verCode);

                // Verify Birthday
                verificationCode = checkDigits(zoneBirthDate);
                verCode = Integer.parseInt(zoneBirthDateVer);
                final Boolean DateBirthReaded = (verificationCode == verCode);

                // Verify OutDate
                verificationCode = checkDigits(zoneOutDate);
                verCode = Integer.parseInt(zoneOutDateVer);
                final Boolean OutDateReaded = (verificationCode == verCode);

                // Verify DNI
                verificationCode = checkDigits(zoneDNI);
                verCode = Integer.parseInt(zoneDNIVer);
                final Boolean DNIReaded = (verificationCode == verCode);

                // Verify Sex
                final Boolean SexReaded = possibleSexValues.contains(zoneSex);

                // Verify Master
                verificationCode = checkDigits(zonePassportNum + zonePassportNumVer + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer + zoneDNI + zoneDNIVer);
                verCode = Integer.parseInt(zoneMasterVer);
                final Boolean MasterVerificationReaded = (verificationCode == verCode);


                final Boolean allOk = (PassportReaded && DateBirthReaded && OutDateReaded && DNIReaded && MasterVerificationReaded && SexReaded);
                if (allOk) {
                    mOCRTask.mIDType = OCRTask.ID_TYPE_PASSPORT;
                    mOCRTask.mResult = recognizedText;
                    mOCRTask.mState = true;
                    mOCRTask.mName = zoneName.replaceAll("<", " ");
                    mOCRTask.mDNI = zoneDNI;
                    mOCRTask.mCardNumber = zonePassportNum;
                    mOCRTask.mNation = zoneNation;
                    mOCRTask.mSex = zoneSex;

                    DateFormat df = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    mOCRTask.mBirthdayDate = df.parse(zoneBirthDate);
                    mOCRTask.mEndDate = df.parse(zoneOutDate);
                }
            }
        } catch (NumberFormatException e) {
            e.printStackTrace();
        } catch (StringIndexOutOfBoundsException e) {
            e.printStackTrace();
        } catch (ArrayIndexOutOfBoundsException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        mOCRTask.mRunning = false;

            /*FileOutputStream output = null;
            try {
                output = new FileOutputStream(mFile);
                binarizedImage.compress(Bitmap.CompressFormat.PNG, 90, output);
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (null != output) {
                    try {
                        output.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }*/
    }
}