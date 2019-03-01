package org.spongycastle.asn1.x509;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERUTCTime;

public class Time extends ASN1Encodable implements ASN1Choice {
    DERObject time;

    public static Time getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(obj.getObject());
    }

    public Time(DERObject time) {
        if ((time instanceof DERUTCTime) || (time instanceof DERGeneralizedTime)) {
            this.time = time;
            return;
        }
        throw new IllegalArgumentException("unknown object passed to Time");
    }

    public Time(Date date) {
        SimpleTimeZone tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss");
        dateF.setTimeZone(tz);
        String d = dateF.format(date) + "Z";
        int year = Integer.parseInt(d.substring(0, 4));
        if (year < 1950 || year > 2049) {
            this.time = new DERGeneralizedTime(d);
        } else {
            this.time = new DERUTCTime(d.substring(2));
        }
    }

    public static Time getInstance(Object obj) {
        if (obj == null || (obj instanceof Time)) {
            return (Time) obj;
        }
        if (obj instanceof DERUTCTime) {
            return new Time((DERUTCTime) obj);
        }
        if (obj instanceof DERGeneralizedTime) {
            return new Time((DERGeneralizedTime) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public String getTime() {
        if (this.time instanceof DERUTCTime) {
            return ((DERUTCTime) this.time).getAdjustedTime();
        }
        return ((DERGeneralizedTime) this.time).getTime();
    }

    public Date getDate() {
        try {
            if (this.time instanceof DERUTCTime) {
                return ((DERUTCTime) this.time).getAdjustedDate();
            }
            return ((DERGeneralizedTime) this.time).getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("invalid date string: " + e.getMessage());
        }
    }

    public DERObject toASN1Object() {
        return this.time;
    }

    public String toString() {
        return getTime();
    }
}
