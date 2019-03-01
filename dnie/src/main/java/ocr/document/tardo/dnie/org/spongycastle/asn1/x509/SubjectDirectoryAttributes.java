package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class SubjectDirectoryAttributes extends ASN1Encodable {
    private Vector attributes = new Vector();

    public static SubjectDirectoryAttributes getInstance(Object obj) {
        if (obj == null || (obj instanceof SubjectDirectoryAttributes)) {
            return (SubjectDirectoryAttributes) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SubjectDirectoryAttributes((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public SubjectDirectoryAttributes(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            this.attributes.addElement(new Attribute(ASN1Sequence.getInstance(e.nextElement())));
        }
    }

    public SubjectDirectoryAttributes(Vector attributes) {
        Enumeration e = attributes.elements();
        while (e.hasMoreElements()) {
            this.attributes.addElement(e.nextElement());
        }
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        Enumeration e = this.attributes.elements();
        while (e.hasMoreElements()) {
            vec.add((Attribute) e.nextElement());
        }
        return new DERSequence(vec);
    }

    public Vector getAttributes() {
        return this.attributes;
    }
}
