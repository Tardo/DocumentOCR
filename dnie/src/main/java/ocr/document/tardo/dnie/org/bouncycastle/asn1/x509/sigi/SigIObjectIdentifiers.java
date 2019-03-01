package org.bouncycastle.asn1.x509.sigi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface SigIObjectIdentifiers {
    public static final ASN1ObjectIdentifier id_sigi = new ASN1ObjectIdentifier("1.3.36.8");
    public static final ASN1ObjectIdentifier id_sigi_cp = new ASN1ObjectIdentifier(id_sigi + ".1");
    public static final ASN1ObjectIdentifier id_sigi_cp_sigconform = new ASN1ObjectIdentifier(id_sigi_cp + ".1");
    public static final ASN1ObjectIdentifier id_sigi_kp = new ASN1ObjectIdentifier(id_sigi + ".2");
    public static final ASN1ObjectIdentifier id_sigi_kp_directoryService = new ASN1ObjectIdentifier(id_sigi_kp + ".1");
    public static final ASN1ObjectIdentifier id_sigi_on = new ASN1ObjectIdentifier(id_sigi + ".4");
    public static final ASN1ObjectIdentifier id_sigi_on_personalData = new ASN1ObjectIdentifier(id_sigi_on + ".1");
}
