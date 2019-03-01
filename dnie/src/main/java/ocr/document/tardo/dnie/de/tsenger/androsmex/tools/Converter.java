package de.tsenger.androsmex.tools;

import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

public class Converter {
    public static Date BCDtoDate(byte[] yymmdd) {
        int i = 0;
        if (yymmdd == null || yymmdd.length != 6) {
            StringBuilder append = new StringBuilder().append("Argument must have length 6, was ");
            if (yymmdd != null) {
                i = yymmdd.length;
            }
            throw new IllegalArgumentException(append.append(i).toString());
        }
        int year = ((yymmdd[0] * 10) + 2000) + yymmdd[1];
        int month = ((yymmdd[2] * 10) + yymmdd[3]) - 1;
        int day = (yymmdd[4] * 10) + yymmdd[5];
        GregorianCalendar gregCal = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        gregCal.set(year, month, day, 0, 0, 0);
        return gregCal.getTime();
    }

    public static int toUnsignedInt(byte value) {
        return (value < (byte) 0 ? 128 : 0) + (value & CertificateBody.profileType);
    }

    public static long ByteArrayToLong(byte[] bytes) {
        long lo = 0;
        for (int i = 0; i < 8; i++) {
            lo = (lo << 8) + ((long) (bytes[i] & 255));
        }
        return lo;
    }

    public static byte[] longToByteArray(long v) {
        return new byte[]{(byte) ((int) (v >>> 56)), (byte) ((int) (v >>> 48)), (byte) ((int) (v >>> 40)), (byte) ((int) (v >>> 32)), (byte) ((int) (v >>> 24)), (byte) ((int) (v >>> 16)), (byte) ((int) (v >>> 8)), (byte) ((int) (v >>> 0))};
    }

    public static byte[] bigIntToByteArray(BigInteger bi) {
        byte[] temp = bi.toByteArray();
        if (temp[0] != (byte) 0) {
            return temp;
        }
        byte[] returnbytes = new byte[(temp.length - 1)];
        System.arraycopy(temp, 1, returnbytes, 0, returnbytes.length);
        return returnbytes;
    }

    public static ECPoint byteArrayToECPoint(byte[] value, Fp curve) throws IllegalArgumentException {
        byte[] x = new byte[((value.length - 1) / 2)];
        byte[] y = new byte[((value.length - 1) / 2)];
        if (value[0] != (byte) 4) {
            throw new IllegalArgumentException("No uncompressed Point found!");
        }
        System.arraycopy(value, 1, x, 0, (value.length - 1) / 2);
        System.arraycopy(value, ((value.length - 1) / 2) + 1, y, 0, (value.length - 1) / 2);
        return new ECPoint.Fp(curve, new ECFieldElement.Fp(curve.getQ(), new BigInteger(1, x)), new ECFieldElement.Fp(curve.getQ(), new BigInteger(1, y)));
    }
}
