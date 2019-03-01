package org.spongycastle.asn1.misc;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class CAST5CBCParameters extends ASN1Encodable {
    ASN1OctetString iv;
    DERInteger keyLength;

    public static CAST5CBCParameters getInstance(Object o) {
        if (o instanceof CAST5CBCParameters) {
            return (CAST5CBCParameters) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CAST5CBCParameters((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in CAST5CBCParameter factory");
    }

    public CAST5CBCParameters(byte[] iv, int keyLength) {
        this.iv = new DEROctetString(iv);
        this.keyLength = new DERInteger(keyLength);
    }

    public CAST5CBCParameters(ASN1Sequence seq) {
        this.iv = (ASN1OctetString) seq.getObjectAt(0);
        this.keyLength = (DERInteger) seq.getObjectAt(1);
    }

    public byte[] getIV() {
        return this.iv.getOctets();
    }

    public int getKeyLength() {
        return this.keyLength.getValue().intValue();
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.iv);
        v.add(this.keyLength);
        return new DERSequence(v);
    }
}
