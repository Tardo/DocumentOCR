package org.spongycastle.asn1.x509.qualified;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERPrintableString;

public class Iso4217CurrencyCode extends ASN1Encodable implements ASN1Choice {
    final int ALPHABETIC_MAXSIZE = 3;
    final int NUMERIC_MAXSIZE = 999;
    final int NUMERIC_MINSIZE = 1;
    int numeric;
    DEREncodable obj;

    public static Iso4217CurrencyCode getInstance(Object obj) {
        if (obj == null || (obj instanceof Iso4217CurrencyCode)) {
            return (Iso4217CurrencyCode) obj;
        }
        if (obj instanceof DERInteger) {
            return new Iso4217CurrencyCode(DERInteger.getInstance(obj).getValue().intValue());
        }
        if (obj instanceof DERPrintableString) {
            return new Iso4217CurrencyCode(DERPrintableString.getInstance(obj).getString());
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public Iso4217CurrencyCode(int numeric) {
        if (numeric > 999 || numeric < 1) {
            throw new IllegalArgumentException("wrong size in numeric code : not in (1..999)");
        }
        this.obj = new DERInteger(numeric);
    }

    public Iso4217CurrencyCode(String alphabetic) {
        if (alphabetic.length() > 3) {
            throw new IllegalArgumentException("wrong size in alphabetic code : max size is 3");
        }
        this.obj = new DERPrintableString(alphabetic);
    }

    public boolean isAlphabetic() {
        return this.obj instanceof DERPrintableString;
    }

    public String getAlphabetic() {
        return ((DERPrintableString) this.obj).getString();
    }

    public int getNumeric() {
        return ((DERInteger) this.obj).getValue().intValue();
    }

    public DERObject toASN1Object() {
        return this.obj.getDERObject();
    }
}
