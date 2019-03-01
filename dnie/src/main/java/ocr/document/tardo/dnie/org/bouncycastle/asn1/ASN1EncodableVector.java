package org.bouncycastle.asn1;

import java.util.Enumeration;
import java.util.Vector;

public class ASN1EncodableVector {
    /* renamed from: v */
    Vector f44v = new Vector();

    public void add(ASN1Encodable aSN1Encodable) {
        this.f44v.addElement(aSN1Encodable);
    }

    public void addAll(ASN1EncodableVector aSN1EncodableVector) {
        Enumeration elements = aSN1EncodableVector.f44v.elements();
        while (elements.hasMoreElements()) {
            this.f44v.addElement(elements.nextElement());
        }
    }

    public ASN1Encodable get(int i) {
        return (ASN1Encodable) this.f44v.elementAt(i);
    }

    public int size() {
        return this.f44v.size();
    }
}
