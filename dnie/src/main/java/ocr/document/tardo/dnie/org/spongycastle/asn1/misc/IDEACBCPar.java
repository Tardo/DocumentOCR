package org.spongycastle.asn1.misc;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class IDEACBCPar extends ASN1Encodable {
    ASN1OctetString iv;

    public static IDEACBCPar getInstance(Object o) {
        if (o instanceof IDEACBCPar) {
            return (IDEACBCPar) o;
        }
        if (o instanceof ASN1Sequence) {
            return new IDEACBCPar((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("unknown object in IDEACBCPar factory");
    }

    public IDEACBCPar(byte[] iv) {
        this.iv = new DEROctetString(iv);
    }

    public IDEACBCPar(ASN1Sequence seq) {
        if (seq.size() == 1) {
            this.iv = (ASN1OctetString) seq.getObjectAt(0);
        } else {
            this.iv = null;
        }
    }

    public byte[] getIV() {
        if (this.iv != null) {
            return this.iv.getOctets();
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.iv != null) {
            v.add(this.iv);
        }
        return new DERSequence(v);
    }
}
