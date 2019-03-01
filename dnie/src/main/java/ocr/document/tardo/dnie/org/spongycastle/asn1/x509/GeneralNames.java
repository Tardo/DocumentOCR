package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class GeneralNames extends ASN1Encodable {
    private final GeneralName[] names;

    public static GeneralNames getInstance(Object obj) {
        if (obj == null || (obj instanceof GeneralNames)) {
            return (GeneralNames) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new GeneralNames((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static GeneralNames getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public GeneralNames(GeneralName name) {
        this.names = new GeneralName[]{name};
    }

    public GeneralNames(ASN1Sequence seq) {
        this.names = new GeneralName[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.names[i] = GeneralName.getInstance(seq.getObjectAt(i));
        }
    }

    public GeneralName[] getNames() {
        GeneralName[] tmp = new GeneralName[this.names.length];
        System.arraycopy(this.names, 0, tmp, 0, this.names.length);
        return tmp;
    }

    public DERObject toASN1Object() {
        return new DERSequence(this.names);
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String sep = System.getProperty("line.separator");
        buf.append("GeneralNames:");
        buf.append(sep);
        for (int i = 0; i != this.names.length; i++) {
            buf.append("    ");
            buf.append(this.names[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}