package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class IssuerSerial extends ASN1Encodable {
    GeneralNames issuer;
    DERBitString issuerUID;
    DERInteger serial;

    public static IssuerSerial getInstance(Object obj) {
        if (obj == null || (obj instanceof IssuerSerial)) {
            return (IssuerSerial) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new IssuerSerial((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static IssuerSerial getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public IssuerSerial(ASN1Sequence seq) {
        if (seq.size() == 2 || seq.size() == 3) {
            this.issuer = GeneralNames.getInstance(seq.getObjectAt(0));
            this.serial = DERInteger.getInstance(seq.getObjectAt(1));
            if (seq.size() == 3) {
                this.issuerUID = DERBitString.getInstance(seq.getObjectAt(2));
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public IssuerSerial(GeneralNames issuer, DERInteger serial) {
        this.issuer = issuer;
        this.serial = serial;
    }

    public GeneralNames getIssuer() {
        return this.issuer;
    }

    public DERInteger getSerial() {
        return this.serial;
    }

    public DERBitString getIssuerUID() {
        return this.issuerUID;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.issuer);
        v.add(this.serial);
        if (this.issuerUID != null) {
            v.add(this.issuerUID);
        }
        return new DERSequence(v);
    }
}
