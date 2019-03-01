package org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import org.bouncycastle.pqc.math.linearalgebra.Matrix;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class DERGeneralizedTime extends ASN1Primitive {
    private byte[] time;

    public DERGeneralizedTime(String str) {
        this.time = Strings.toByteArray(str);
        try {
            getDate();
        } catch (ParseException e) {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    public DERGeneralizedTime(Date date) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.time = Strings.toByteArray(simpleDateFormat.format(date));
    }

    DERGeneralizedTime(byte[] bArr) {
        this.time = bArr;
    }

    private String calculateGMTOffset() {
        String str = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int rawOffset = timeZone.getRawOffset();
        if (rawOffset < 0) {
            str = "-";
            rawOffset = -rawOffset;
        }
        int i = rawOffset / 3600000;
        int i2 = (rawOffset - (((i * 60) * 60) * 1000)) / 60000;
        try {
            if (timeZone.useDaylightTime() && timeZone.inDaylightTime(getDate())) {
                rawOffset = (str.equals("+") ? 1 : -1) + i;
                return "GMT" + str + convert(rawOffset) + ":" + convert(i2);
            }
            rawOffset = i;
            return "GMT" + str + convert(rawOffset) + ":" + convert(i2);
        } catch (ParseException e) {
            rawOffset = i;
        }
    }

    private String convert(int i) {
        return i < 10 ? "0" + i : Integer.toString(i);
    }

    public static ASN1GeneralizedTime getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1GeneralizedTime)) {
            return (ASN1GeneralizedTime) obj;
        }
        if (obj instanceof DERGeneralizedTime) {
            return new ASN1GeneralizedTime(((DERGeneralizedTime) obj).time);
        }
        if (obj instanceof byte[]) {
            try {
                return (ASN1GeneralizedTime) ASN1Primitive.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1GeneralizedTime getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERGeneralizedTime)) ? getInstance(object) : new ASN1GeneralizedTime(((ASN1OctetString) object).getOctets());
    }

    private boolean hasFractionalSeconds() {
        int i = 0;
        while (i != this.time.length) {
            if (this.time[i] == (byte) 46 && i == 14) {
                return true;
            }
            i++;
        }
        return false;
    }

    boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        return !(aSN1Primitive instanceof DERGeneralizedTime) ? false : Arrays.areEqual(this.time, ((DERGeneralizedTime) aSN1Primitive).time);
    }

    void encode(ASN1OutputStream aSN1OutputStream) throws IOException {
        aSN1OutputStream.writeEncoded(24, this.time);
    }

    int encodedLength() {
        int length = this.time.length;
        return length + (StreamUtil.calculateBodyLength(length) + 1);
    }

    public Date getDate() throws ParseException {
        SimpleDateFormat simpleDateFormat;
        String str;
        String fromByteArray = Strings.fromByteArray(this.time);
        SimpleDateFormat simpleDateFormat2;
        String str2;
        if (fromByteArray.endsWith("Z")) {
            simpleDateFormat2 = hasFractionalSeconds() ? new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'") : new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            simpleDateFormat2.setTimeZone(new SimpleTimeZone(0, "Z"));
            str2 = fromByteArray;
            simpleDateFormat = simpleDateFormat2;
            str = str2;
        } else if (fromByteArray.indexOf(45) > 0 || fromByteArray.indexOf(43) > 0) {
            fromByteArray = getTime();
            simpleDateFormat2 = hasFractionalSeconds() ? new SimpleDateFormat("yyyyMMddHHmmss.SSSz") : new SimpleDateFormat("yyyyMMddHHmmssz");
            simpleDateFormat2.setTimeZone(new SimpleTimeZone(0, "Z"));
            str2 = fromByteArray;
            simpleDateFormat = simpleDateFormat2;
            str = str2;
        } else {
            simpleDateFormat2 = hasFractionalSeconds() ? new SimpleDateFormat("yyyyMMddHHmmss.SSS") : new SimpleDateFormat("yyyyMMddHHmmss");
            simpleDateFormat2.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
            str2 = fromByteArray;
            simpleDateFormat = simpleDateFormat2;
            str = str2;
        }
        if (hasFractionalSeconds()) {
            String substring = str.substring(14);
            int i = 1;
            while (i < substring.length()) {
                char charAt = substring.charAt(i);
                if ('0' > charAt || charAt > '9') {
                    break;
                }
                i++;
            }
            if (i - 1 > 3) {
                str = str.substring(0, 14) + (substring.substring(0, 4) + substring.substring(i));
            } else if (i - 1 == 1) {
                str = str.substring(0, 14) + (substring.substring(0, i) + "00" + substring.substring(i));
            } else if (i - 1 == 2) {
                str = str.substring(0, 14) + (substring.substring(0, i) + "0" + substring.substring(i));
            }
        }
        return simpleDateFormat.parse(str);
    }

    public String getTime() {
        String fromByteArray = Strings.fromByteArray(this.time);
        if (fromByteArray.charAt(fromByteArray.length() - 1) == Matrix.MATRIX_TYPE_ZERO) {
            return fromByteArray.substring(0, fromByteArray.length() - 1) + "GMT+00:00";
        }
        int length = fromByteArray.length() - 5;
        char charAt = fromByteArray.charAt(length);
        if (charAt == '-' || charAt == '+') {
            return fromByteArray.substring(0, length) + "GMT" + fromByteArray.substring(length, length + 3) + ":" + fromByteArray.substring(length + 3);
        }
        length = fromByteArray.length() - 3;
        charAt = fromByteArray.charAt(length);
        return (charAt == '-' || charAt == '+') ? fromByteArray.substring(0, length) + "GMT" + fromByteArray.substring(length) + ":00" : fromByteArray + calculateGMTOffset();
    }

    public String getTimeString() {
        return Strings.fromByteArray(this.time);
    }

    public int hashCode() {
        return Arrays.hashCode(this.time);
    }

    boolean isConstructed() {
        return false;
    }
}
