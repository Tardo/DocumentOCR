package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class AuthorityInformationAccess extends ASN1Encodable {
    private AccessDescription[] descriptions;

    public static AuthorityInformationAccess getInstance(Object obj) {
        if (obj instanceof AuthorityInformationAccess) {
            return (AuthorityInformationAccess) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new AuthorityInformationAccess((ASN1Sequence) obj);
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AuthorityInformationAccess(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("sequence may not be empty");
        }
        this.descriptions = new AccessDescription[seq.size()];
        for (int i = 0; i != seq.size(); i++) {
            this.descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
        }
    }

    public AuthorityInformationAccess(DERObjectIdentifier oid, GeneralName location) {
        this.descriptions = new AccessDescription[1];
        this.descriptions[0] = new AccessDescription(oid, location);
    }

    public AccessDescription[] getAccessDescriptions() {
        return this.descriptions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i != this.descriptions.length; i++) {
            vec.add(this.descriptions[i]);
        }
        return new DERSequence(vec);
    }

    public String toString() {
        return "AuthorityInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")";
    }
}
