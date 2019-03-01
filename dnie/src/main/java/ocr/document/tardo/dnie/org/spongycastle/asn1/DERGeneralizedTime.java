package org.spongycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import org.bouncycastle.pqc.math.linearalgebra.Matrix;

public class DERGeneralizedTime extends ASN1Object {
    String time;

    public static DERGeneralizedTime getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGeneralizedTime)) {
            return (DERGeneralizedTime) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERGeneralizedTime getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERGeneralizedTime)) {
            return getInstance(o);
        }
        return new DERGeneralizedTime(((ASN1OctetString) o).getOctets());
    }

    public DERGeneralizedTime(String time) {
        this.time = time;
        try {
            getDate();
        } catch (ParseException e) {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    public DERGeneralizedTime(Date time) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.time = dateF.format(time);
    }

    DERGeneralizedTime(byte[] bytes) {
        char[] dateC = new char[bytes.length];
        for (int i = 0; i != dateC.length; i++) {
            dateC[i] = (char) (bytes[i] & 255);
        }
        this.time = new String(dateC);
    }

    public String getTimeString() {
        return this.time;
    }

    public String getTime() {
        if (this.time.charAt(this.time.length() - 1) == Matrix.MATRIX_TYPE_ZERO) {
            return this.time.substring(0, this.time.length() - 1) + "GMT+00:00";
        }
        int signPos = this.time.length() - 5;
        char sign = this.time.charAt(signPos);
        if (sign == '-' || sign == '+') {
            return this.time.substring(0, signPos) + "GMT" + this.time.substring(signPos, signPos + 3) + ":" + this.time.substring(signPos + 3);
        }
        signPos = this.time.length() - 3;
        sign = this.time.charAt(signPos);
        if (sign == '-' || sign == '+') {
            return this.time.substring(0, signPos) + "GMT" + this.time.substring(signPos) + ":00";
        }
        return this.time + calculateGMTOffset();
    }

    private String calculateGMTOffset() {
        String sign = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0) {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / 3600000;
        int minutes = (offset - (((hours * 60) * 60) * 1000)) / 60000;
        try {
            if (timeZone.useDaylightTime() && timeZone.inDaylightTime(getDate())) {
                hours += sign.equals("+") ? 1 : -1;
            }
        } catch (ParseException e) {
        }
        return "GMT" + sign + convert(hours) + ":" + convert(minutes);
    }

    private String convert(int time) {
        if (time < 10) {
            return "0" + time;
        }
        return Integer.toString(time);
    }

    public Date getDate() throws ParseException {
        SimpleDateFormat dateF;
        String d = this.time;
        if (this.time.endsWith("Z")) {
            if (hasFractionalSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
            } else {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            }
            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        } else if (this.time.indexOf(45) > 0 || this.time.indexOf(43) > 0) {
            d = getTime();
            if (hasFractionalSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
            } else {
                dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
            }
            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        } else {
            if (hasFractionalSeconds()) {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
            } else {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss");
            }
            dateF.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
        }
        if (hasFractionalSeconds()) {
            String frac = d.substring(14);
            int index = 1;
            while (index < frac.length()) {
                char ch = frac.charAt(index);
                if ('0' > ch || ch > '9') {
                    break;
                }
                index++;
            }
            if (index - 1 > 3) {
                d = d.substring(0, 14) + (frac.substring(0, 4) + frac.substring(index));
            } else if (index - 1 == 1) {
                d = d.substring(0, 14) + (frac.substring(0, index) + "00" + frac.substring(index));
            } else if (index - 1 == 2) {
                d = d.substring(0, 14) + (frac.substring(0, index) + "0" + frac.substring(index));
            }
        }
        return dateF.parse(d);
    }

    private boolean hasFractionalSeconds() {
        return this.time.indexOf(46) == 14;
    }

    private byte[] getOctets() {
        char[] cs = this.time.toCharArray();
        byte[] bs = new byte[cs.length];
        for (int i = 0; i != cs.length; i++) {
            bs[i] = (byte) cs[i];
        }
        return bs;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(24, getOctets());
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERGeneralizedTime) {
            return this.time.equals(((DERGeneralizedTime) o).time);
        }
        return false;
    }

    public int hashCode() {
        return this.time.hashCode();
    }
}
