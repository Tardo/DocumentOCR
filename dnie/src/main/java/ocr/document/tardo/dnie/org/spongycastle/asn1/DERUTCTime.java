package org.spongycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

public class DERUTCTime extends ASN1Object {
    String time;

    public static DERUTCTime getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUTCTime)) {
            return (DERUTCTime) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERUTCTime getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERUTCTime)) {
            return getInstance(o);
        }
        return new DERUTCTime(((ASN1OctetString) o).getOctets());
    }

    public DERUTCTime(String time) {
        this.time = time;
        try {
            getDate();
        } catch (ParseException e) {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    public DERUTCTime(Date time) {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'");
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        this.time = dateF.format(time);
    }

    DERUTCTime(byte[] bytes) {
        char[] dateC = new char[bytes.length];
        for (int i = 0; i != dateC.length; i++) {
            dateC[i] = (char) (bytes[i] & 255);
        }
        this.time = new String(dateC);
    }

    public Date getDate() throws ParseException {
        return new SimpleDateFormat("yyMMddHHmmssz").parse(getTime());
    }

    public Date getAdjustedDate() throws ParseException {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        return dateF.parse(getAdjustedTime());
    }

    public String getTime() {
        if (this.time.indexOf(45) >= 0 || this.time.indexOf(43) >= 0) {
            int index = this.time.indexOf(45);
            if (index < 0) {
                index = this.time.indexOf(43);
            }
            String d = this.time;
            if (index == this.time.length() - 3) {
                d = d + "00";
            }
            if (index == 10) {
                return d.substring(0, 10) + "00GMT" + d.substring(10, 13) + ":" + d.substring(13, 15);
            }
            return d.substring(0, 12) + "GMT" + d.substring(12, 15) + ":" + d.substring(15, 17);
        } else if (this.time.length() == 11) {
            return this.time.substring(0, 10) + "00GMT+00:00";
        } else {
            return this.time.substring(0, 12) + "GMT+00:00";
        }
    }

    public String getAdjustedTime() {
        String d = getTime();
        if (d.charAt(0) < '5') {
            return "20" + d;
        }
        return "19" + d;
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
        out.writeEncoded(23, getOctets());
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERUTCTime) {
            return this.time.equals(((DERUTCTime) o).time);
        }
        return false;
    }

    public int hashCode() {
        return this.time.hashCode();
    }

    public String toString() {
        return this.time;
    }
}
