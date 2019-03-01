package org.spongycastle.asn1.cmp;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERUTF8String;

public class PKIFreeText extends ASN1Encodable {
    ASN1Sequence strings;

    public static PKIFreeText getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIFreeText getInstance(Object obj) {
        if (obj instanceof PKIFreeText) {
            return (PKIFreeText) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PKIFreeText((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Unknown object in factory: " + obj.getClass().getName());
    }

    public PKIFreeText(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            if (!(e.nextElement() instanceof DERUTF8String)) {
                throw new IllegalArgumentException("attempt to insert non UTF8 STRING into PKIFreeText");
            }
        }
        this.strings = seq;
    }

    public PKIFreeText(DERUTF8String p) {
        this.strings = new DERSequence((DEREncodable) p);
    }

    public PKIFreeText(DERUTF8String[] strs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (DEREncodable add : strs) {
            v.add(add);
        }
        this.strings = new DERSequence(v);
    }

    public PKIFreeText(String[] strs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (String dERUTF8String : strs) {
            v.add(new DERUTF8String(dERUTF8String));
        }
        this.strings = new DERSequence(v);
    }

    public int size() {
        return this.strings.size();
    }

    public DERUTF8String getStringAt(int i) {
        return (DERUTF8String) this.strings.getObjectAt(i);
    }

    public DERObject toASN1Object() {
        return this.strings;
    }
}
