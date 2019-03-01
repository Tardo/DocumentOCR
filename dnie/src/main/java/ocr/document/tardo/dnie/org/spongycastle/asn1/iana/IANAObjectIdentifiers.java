package org.spongycastle.asn1.iana;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

public interface IANAObjectIdentifiers {
    public static final ASN1ObjectIdentifier hmacMD5 = new ASN1ObjectIdentifier(isakmpOakley + ".1");
    public static final ASN1ObjectIdentifier hmacRIPEMD160 = new ASN1ObjectIdentifier(isakmpOakley + ".4");
    public static final ASN1ObjectIdentifier hmacSHA1 = new ASN1ObjectIdentifier(isakmpOakley + ".2");
    public static final ASN1ObjectIdentifier hmacTIGER = new ASN1ObjectIdentifier(isakmpOakley + ".3");
    public static final ASN1ObjectIdentifier isakmpOakley = new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1");
}
