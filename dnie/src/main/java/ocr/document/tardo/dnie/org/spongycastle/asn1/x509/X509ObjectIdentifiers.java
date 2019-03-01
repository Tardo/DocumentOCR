package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

public interface X509ObjectIdentifiers {
    public static final ASN1ObjectIdentifier commonName = new ASN1ObjectIdentifier("2.5.4.3");
    public static final ASN1ObjectIdentifier countryName = new ASN1ObjectIdentifier("2.5.4.6");
    public static final ASN1ObjectIdentifier crlAccessMethod = id_ad_caIssuers;
    public static final String id = "2.5.4";
    public static final ASN1ObjectIdentifier id_SHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26");
    public static final ASN1ObjectIdentifier id_ad = new ASN1ObjectIdentifier(id_pkix + ".48");
    public static final ASN1ObjectIdentifier id_ad_caIssuers = new ASN1ObjectIdentifier(id_ad + ".2");
    public static final ASN1ObjectIdentifier id_ad_ocsp = new ASN1ObjectIdentifier(id_ad + ".1");
    public static final ASN1ObjectIdentifier id_at_name = new ASN1ObjectIdentifier("2.5.4.41");
    public static final ASN1ObjectIdentifier id_at_telephoneNumber = new ASN1ObjectIdentifier("2.5.4.20");
    public static final ASN1ObjectIdentifier id_ea_rsa = new ASN1ObjectIdentifier("2.5.8.1.1");
    public static final ASN1ObjectIdentifier id_pe = new ASN1ObjectIdentifier(id_pkix + ".1");
    public static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
    public static final ASN1ObjectIdentifier localityName = new ASN1ObjectIdentifier("2.5.4.7");
    public static final ASN1ObjectIdentifier ocspAccessMethod = id_ad_ocsp;
    public static final ASN1ObjectIdentifier organization = new ASN1ObjectIdentifier("2.5.4.10");
    public static final ASN1ObjectIdentifier organizationalUnitName = new ASN1ObjectIdentifier("2.5.4.11");
    public static final ASN1ObjectIdentifier ripemd160 = new ASN1ObjectIdentifier("1.3.36.3.2.1");
    public static final ASN1ObjectIdentifier ripemd160WithRSAEncryption = new ASN1ObjectIdentifier("1.3.36.3.3.1.2");
    public static final ASN1ObjectIdentifier stateOrProvinceName = new ASN1ObjectIdentifier("2.5.4.8");
}
