package org.spongycastle.asn1.tsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;

public class Accuracy extends ASN1Encodable {
    protected static final int MAX_MICROS = 999;
    protected static final int MAX_MILLIS = 999;
    protected static final int MIN_MICROS = 1;
    protected static final int MIN_MILLIS = 1;
    DERInteger micros;
    DERInteger millis;
    DERInteger seconds;

    protected Accuracy() {
    }

    public Accuracy(DERInteger seconds, DERInteger millis, DERInteger micros) {
        this.seconds = seconds;
        if (millis == null || (millis.getValue().intValue() >= 1 && millis.getValue().intValue() <= 999)) {
            this.millis = millis;
            if (micros == null || (micros.getValue().intValue() >= 1 && micros.getValue().intValue() <= 999)) {
                this.micros = micros;
                return;
            }
            throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
        }
        throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
    }

    public Accuracy(ASN1Sequence seq) {
        this.seconds = null;
        this.millis = null;
        this.micros = null;
        for (int i = 0; i < seq.size(); i++) {
            if (seq.getObjectAt(i) instanceof DERInteger) {
                this.seconds = (DERInteger) seq.getObjectAt(i);
            } else if (seq.getObjectAt(i) instanceof DERTaggedObject) {
                DERTaggedObject extra = (DERTaggedObject) seq.getObjectAt(i);
                switch (extra.getTagNo()) {
                    case 0:
                        this.millis = DERInteger.getInstance(extra, false);
                        if (this.millis.getValue().intValue() >= 1 && this.millis.getValue().intValue() <= 999) {
                            break;
                        }
                        throw new IllegalArgumentException("Invalid millis field : not in (1..999).");
                        break;
                    case 1:
                        this.micros = DERInteger.getInstance(extra, false);
                        if (this.micros.getValue().intValue() >= 1 && this.micros.getValue().intValue() <= 999) {
                            break;
                        }
                        throw new IllegalArgumentException("Invalid micros field : not in (1..999).");
                    default:
                        throw new IllegalArgumentException("Invalig tag number");
                }
            } else {
                continue;
            }
        }
    }

    public static Accuracy getInstance(Object o) {
        if (o == null || (o instanceof Accuracy)) {
            return (Accuracy) o;
        }
        if (o instanceof ASN1Sequence) {
            return new Accuracy((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Unknown object in 'Accuracy' factory : " + o.getClass().getName() + ".");
    }

    public DERInteger getSeconds() {
        return this.seconds;
    }

    public DERInteger getMillis() {
        return this.millis;
    }

    public DERInteger getMicros() {
        return this.micros;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.seconds != null) {
            v.add(this.seconds);
        }
        if (this.millis != null) {
            v.add(new DERTaggedObject(false, 0, this.millis));
        }
        if (this.micros != null) {
            v.add(new DERTaggedObject(false, 1, this.micros));
        }
        return new DERSequence(v);
    }
}
