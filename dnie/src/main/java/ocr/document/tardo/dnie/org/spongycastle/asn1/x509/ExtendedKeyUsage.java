package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class ExtendedKeyUsage extends ASN1Encodable {
    ASN1Sequence seq;
    Hashtable usageTable = new Hashtable();

    public static ExtendedKeyUsage getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtendedKeyUsage getInstance(Object obj) {
        if (obj instanceof ExtendedKeyUsage) {
            return (ExtendedKeyUsage) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ExtendedKeyUsage((ASN1Sequence) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("Invalid ExtendedKeyUsage: " + obj.getClass().getName());
    }

    public ExtendedKeyUsage(KeyPurposeId usage) {
        this.seq = new DERSequence((DEREncodable) usage);
        this.usageTable.put(usage, usage);
    }

    public ExtendedKeyUsage(ASN1Sequence seq) {
        this.seq = seq;
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            Object o = e.nextElement();
            if (o instanceof DERObjectIdentifier) {
                this.usageTable.put(o, o);
            } else {
                throw new IllegalArgumentException("Only DERObjectIdentifiers allowed in ExtendedKeyUsage.");
            }
        }
    }

    public ExtendedKeyUsage(Vector usages) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        Enumeration e = usages.elements();
        while (e.hasMoreElements()) {
            DERObject o = (DERObject) e.nextElement();
            v.add(o);
            this.usageTable.put(o, o);
        }
        this.seq = new DERSequence(v);
    }

    public boolean hasKeyPurposeId(KeyPurposeId keyPurposeId) {
        return this.usageTable.get(keyPurposeId) != null;
    }

    public Vector getUsages() {
        Vector temp = new Vector();
        Enumeration it = this.usageTable.elements();
        while (it.hasMoreElements()) {
            temp.addElement(it.nextElement());
        }
        return temp;
    }

    public int size() {
        return this.usageTable.size();
    }

    public DERObject toASN1Object() {
        return this.seq;
    }
}
