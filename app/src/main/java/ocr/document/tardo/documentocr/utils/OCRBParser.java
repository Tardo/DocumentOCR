/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.utils;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/* Spain OCR format: https://josep-portella.com/es/escritos/desmitificando-los-numeros-del-dni/ */
public class OCRBParser {

    private static int checkDigits(String toVerify) {
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

    private static String getNifNieLetter(String nif) {
        final String letras = "TRWAGMYFPDXBNJZSQVHLCKE";
        final int dni = Integer.parseInt(nif) % 23;
        return letras.substring(dni, dni + 1);
    }

    private static boolean isNifNie(String nif) {
        // If NIE, remove initial x,y,z
        if (nif.toUpperCase().startsWith("X") || nif.toUpperCase().startsWith("Y") || nif.toUpperCase().startsWith("Z"))
            nif = nif.substring(1);

        final Pattern nifPattern = Pattern.compile("(\\d{1,8})([TRWAGMYFPDXBNJZSQVHLCKEtrwagmyfpdxbnjzsqvhlcke])");
        final Matcher m = nifPattern.matcher(nif);
        if (m.matches())
            return getNifNieLetter(m.group(1)).equalsIgnoreCase(m.group(2));
        else
            return false;
    }

    public static OCRInfo run(String data) {
        OCRInfo result = null;

        ArrayList<String> possibleSexValues = new ArrayList<String>();
        possibleSexValues.add("F");
        possibleSexValues.add("M");
        possibleSexValues.add("<");

        String[] lines = data.split(System.getProperty("line.separator"));
        try {
            if ('<' != lines[0].charAt(lines[0].length() - 7)) {
                // DNIe
                final int[][] zones = new int[][]{
                        {0, 2},     // Type
                        {2, 5},     // Country
                        {5, 14},    // Card Serial Number
                        {14, 15},   // Control Digit: Card Serial Number
                        {15, 24},   // DNI

                        {0, 6},     // Birthday
                        {6, 7},     // Control Digit: Birthday
                        {7, 8},     // Gender (M/F)
                        {8, 14},    // Caducity
                        {14, 15},   // Digit Control: Caducity
                        {15, 18},   // Nationality
                        {29, 30},   // Master Digit Control

                        {0, 30},    // Name
                };

                String zoneCardNumber = lines[0].substring(zones[2][0], zones[2][1]);
                String zoneCardNumberVer = lines[0].substring(zones[3][0], zones[3][1]);
                String zoneDNI = lines[0].substring(zones[4][0], zones[4][1]);
                String zoneBirthDate = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneBirthDateVer = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneGender = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneOutDate = lines[1].substring(zones[8][0], zones[8][1]);
                String zoneOutDateVer = lines[1].substring(zones[9][0], zones[9][1]);
                String zoneCountry = lines[1].substring(zones[10][0], zones[10][1]);
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
                final Boolean SexReaded = possibleSexValues.contains(zoneGender);

                // Verify Master
                String toVerify = zoneCardNumber + zoneCardNumberVer + zoneDNI + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer;
                verificationCode = checkDigits(toVerify);
                verCode = Integer.parseInt(lines[1].substring(zones[11][0], zones[11][1]));
                final Boolean MasterVerificationReaded = (verificationCode == verCode);

                final Boolean allOk = (CardNumberReaded && DateBirthReaded && OutDateReaded && MasterVerificationReaded && DNIReaded && SexReaded);
                if (allOk) {
                    result = new OCRInfo();
                    result.mRaw = data;
                    result.mName = zoneName.replaceAll("<", " ");
                    result.mDNI = zoneDNI;
                    result.mCardNumber = zoneCardNumber;
                    result.mCountry = zoneCountry;
                    result.mGender = zoneGender;

                    DateFormat df = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    result.mBirthdayDate = df.parse(zoneBirthDate);
                    result.mEndDate = df.parse(zoneOutDate);
                }
            } else if (lines.length >= 3) {
                // DNI Traditional
                final int[][] zones = new int[][]{
                        {0, 2},     // Type
                        {2, 5},     // Country
                        {5, 14},    // DNI
                        {14, 15},   // Control Digit: DNI

                        {0, 6},     // Birthday
                        {6, 7},     // Control Digit: Birthday
                        {7, 8},     // Gender (M/F)
                        {8, 14},    // Caducity
                        {14, 15},   // Control Digit: Caducity
                        {15, 18},   // Nationality
                        {29, 30},   // Master Control Digit

                        {0, 30},    // Name
                };

                String zoneDNI = lines[0].substring(zones[2][0], zones[2][1]);
                String zoneDNIVer = lines[0].substring(zones[3][0], zones[3][1]);
                String zoneBirthDate = lines[1].substring(zones[4][0], zones[4][1]);
                String zoneBirthDateVer = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneGender = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneOutDate = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneOutDateVer = lines[1].substring(zones[8][0], zones[8][1]);
                String zoneCountry = lines[1].substring(zones[9][0], zones[9][1]);
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
                final Boolean SexReaded = possibleSexValues.contains(zoneGender);

                // Verify Master
                String toVerify = zoneDNI + zoneDNIVer + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer;
                verificationCode = checkDigits(toVerify);
                verCode = Integer.parseInt(lines[1].substring(zones[10][0], zones[10][1]));
                final Boolean MasterVerificationReaded = (verificationCode == verCode);

                final Boolean allOk = (DNIReaded && DateBirthReaded && OutDateReaded && MasterVerificationReaded && SexReaded);
                if (allOk) {
                    result = new OCRInfo();
                    result.mRaw = data;
                    result.mIDType = OCRInfo.ID_TYPE_TRADITIONAL;
                    result.mName = zoneName.replaceAll("<", " ");
                    result.mDNI = zoneDNI;
                    result.mCountry = zoneCountry;
                    result.mGender = zoneGender;

                    DateFormat dfB = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    result.mBirthdayDate = dfB.parse(zoneBirthDate);
                    DateFormat dfE = new SimpleDateFormat("ddMMyy", Locale.ENGLISH);
                    result.mEndDate = dfE.parse(zoneOutDate);
                }
            } else {
                // Passport
                final int[][] zones = new int[][]{
                        {0, 1},     // Type
                        {2, 5},     // Country
                        {5, 43},    // Name

                        {0, 9},     // Passport Serial Number
                        {9, 10},    // Control Digit: Passport Serial Number
                        {10, 13},   // Nationality
                        {13, 19},   // Birthday
                        {19, 20},   // Control Digit: Birthday
                        {20, 21},   // Gender
                        {21, 27},   // Caducity
                        {27, 28},   // Control Digit: Caducity
                        {28, 39},   // DNI (Passport Format)
                        {42, 43},   // Control Digit: DNI (Passport Format)
                        {43, 44},   // Master Control Digitt
                };

                String zoneName = lines[0].substring(zones[2][0], zones[2][1]);
                String zonePassportNum = lines[1].substring(zones[3][0], zones[3][1]);
                String zonePassportNumVer = lines[1].substring(zones[4][0], zones[4][1]);
                String zoneCountry = lines[1].substring(zones[5][0], zones[5][1]);
                String zoneBirthDate = lines[1].substring(zones[6][0], zones[6][1]);
                String zoneBirthDateVer = lines[1].substring(zones[7][0], zones[7][1]);
                String zoneGender = lines[1].substring(zones[8][0], zones[8][1]);
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
                final Boolean SexReaded = possibleSexValues.contains(zoneGender);

                // Verify Master
                verificationCode = checkDigits(zonePassportNum + zonePassportNumVer + zoneBirthDate + zoneBirthDateVer + zoneOutDate + zoneOutDateVer + zoneDNI + zoneDNIVer);
                verCode = Integer.parseInt(zoneMasterVer);
                final Boolean MasterVerificationReaded = (verificationCode == verCode);


                final Boolean allOk = (PassportReaded && DateBirthReaded && OutDateReaded && DNIReaded && MasterVerificationReaded && SexReaded);
                if (allOk) {
                    result = new OCRInfo();
                    result.mIDType = OCRInfo.ID_TYPE_PASSPORT;
                    result.mRaw = data;
                    result.mName = zoneName.replaceAll("<", " ");
                    result.mDNI = zoneDNI;
                    result.mCardNumber = zonePassportNum;
                    result.mCountry = zoneCountry;
                    result.mGender = zoneGender;

                    DateFormat df = new SimpleDateFormat("yyMMdd", Locale.ENGLISH);
                    result.mBirthdayDate = df.parse(zoneBirthDate);
                    result.mEndDate = df.parse(zoneOutDate);
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

        return result;
    }
}
