package org.spongycastle.asn1;

public class ASN1ObjectIdentifier extends DERObjectIdentifier {
    public ASN1ObjectIdentifier(String identifier) {
        super(identifier);
    }

    ASN1ObjectIdentifier(byte[] bytes) {
        super(bytes);
    }

    public ASN1ObjectIdentifier branch(String branchID) {
        return new ASN1ObjectIdentifier(getId() + "." + branchID);
    }
}