package org.spongycastle.jce.interfaces;

import java.util.Enumeration;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObjectIdentifier;

public interface PKCS12BagAttributeCarrier {
    DEREncodable getBagAttribute(DERObjectIdentifier dERObjectIdentifier);

    Enumeration getBagAttributeKeys();

    void setBagAttribute(DERObjectIdentifier dERObjectIdentifier, DEREncodable dEREncodable);
}
