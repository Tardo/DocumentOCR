package org.spongycastle.asn1.x509.qualified;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class MonetaryValue extends ASN1Encodable {
    DERInteger amount;
    Iso4217CurrencyCode currency;
    DERInteger exponent;

    public static MonetaryValue getInstance(Object obj) {
        if (obj == null || (obj instanceof MonetaryValue)) {
            return (MonetaryValue) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new MonetaryValue(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public MonetaryValue(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.currency = Iso4217CurrencyCode.getInstance(e.nextElement());
        this.amount = DERInteger.getInstance(e.nextElement());
        this.exponent = DERInteger.getInstance(e.nextElement());
    }

    public MonetaryValue(Iso4217CurrencyCode currency, int amount, int exponent) {
        this.currency = currency;
        this.amount = new DERInteger(amount);
        this.exponent = new DERInteger(exponent);
    }

    public Iso4217CurrencyCode getCurrency() {
        return this.currency;
    }

    public BigInteger getAmount() {
        return this.amount.getValue();
    }

    public BigInteger getExponent() {
        return this.exponent.getValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.currency);
        seq.add(this.amount);
        seq.add(this.exponent);
        return new DERSequence(seq);
    }
}
