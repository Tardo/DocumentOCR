package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.jce.provider.RFC3280CertPathUtilities;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class CertificatePolicies extends ASN1Encodable {
    static final DERObjectIdentifier anyPolicy = new DERObjectIdentifier(RFC3280CertPathUtilities.ANY_POLICY);
    Vector policies;

    public static CertificatePolicies getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertificatePolicies getInstance(Object obj) {
        if (obj instanceof CertificatePolicies) {
            return (CertificatePolicies) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CertificatePolicies((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public CertificatePolicies(ASN1Sequence seq) {
        this.policies = new Vector();
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            this.policies.addElement(ASN1Sequence.getInstance(e.nextElement()).getObjectAt(0));
        }
    }

    public CertificatePolicies(DERObjectIdentifier p) {
        this.policies = new Vector();
        this.policies.addElement(p);
    }

    public CertificatePolicies(String p) {
        this(new DERObjectIdentifier(p));
    }

    public void addPolicy(String p) {
        this.policies.addElement(new DERObjectIdentifier(p));
    }

    public String getPolicy(int nr) {
        if (this.policies.size() > nr) {
            return ((DERObjectIdentifier) this.policies.elementAt(nr)).getId();
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < this.policies.size(); i++) {
            v.add(new DERSequence((DERObjectIdentifier) this.policies.elementAt(i)));
        }
        return new DERSequence(v);
    }

    public String toString() {
        String p = null;
        for (int i = 0; i < this.policies.size(); i++) {
            if (p != null) {
                p = p + ", ";
            }
            p = p + ((DERObjectIdentifier) this.policies.elementAt(i)).getId();
        }
        return "CertificatePolicies: " + p;
    }
}
