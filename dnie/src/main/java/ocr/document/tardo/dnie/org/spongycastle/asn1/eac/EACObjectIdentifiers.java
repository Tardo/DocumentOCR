package org.spongycastle.asn1.eac;

import de.tsenger.androsmex.asn1.BSIObjectIdentifiers;
import org.spongycastle.asn1.DERObjectIdentifier;

public interface EACObjectIdentifiers {
    public static final DERObjectIdentifier bsi_de = new DERObjectIdentifier(BSIObjectIdentifiers.bsi_de);
    public static final DERObjectIdentifier id_CA = new DERObjectIdentifier(bsi_de + ".2.2.3");
    public static final DERObjectIdentifier id_CA_DH = new DERObjectIdentifier(id_CA + ".1");
    public static final DERObjectIdentifier id_CA_DH_3DES_CBC_CBC = new DERObjectIdentifier(id_CA_DH + ".1");
    public static final DERObjectIdentifier id_CA_ECDH = new DERObjectIdentifier(id_CA + ".2");
    public static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new DERObjectIdentifier(id_CA_ECDH + ".1");
    public static final DERObjectIdentifier id_EAC_ePassport = new DERObjectIdentifier(bsi_de + ".3.1.2.1");
    public static final DERObjectIdentifier id_PK = new DERObjectIdentifier(bsi_de + ".2.2.1");
    public static final DERObjectIdentifier id_PK_DH = new DERObjectIdentifier(id_PK + ".1");
    public static final DERObjectIdentifier id_PK_ECDH = new DERObjectIdentifier(id_PK + ".2");
    public static final DERObjectIdentifier id_TA = new DERObjectIdentifier(bsi_de + ".2.2.2");
    public static final DERObjectIdentifier id_TA_ECDSA = new DERObjectIdentifier(id_TA + ".2");
    public static final DERObjectIdentifier id_TA_ECDSA_SHA_1 = new DERObjectIdentifier(id_TA_ECDSA + ".1");
    public static final DERObjectIdentifier id_TA_ECDSA_SHA_224 = new DERObjectIdentifier(id_TA_ECDSA + ".2");
    public static final DERObjectIdentifier id_TA_ECDSA_SHA_256 = new DERObjectIdentifier(id_TA_ECDSA + ".3");
    public static final DERObjectIdentifier id_TA_ECDSA_SHA_384 = new DERObjectIdentifier(id_TA_ECDSA + ".4");
    public static final DERObjectIdentifier id_TA_ECDSA_SHA_512 = new DERObjectIdentifier(id_TA_ECDSA + ".5");
    public static final DERObjectIdentifier id_TA_RSA = new DERObjectIdentifier(id_TA + ".1");
    public static final DERObjectIdentifier id_TA_RSA_PSS_SHA_1 = new DERObjectIdentifier(id_TA_RSA + ".3");
    public static final DERObjectIdentifier id_TA_RSA_PSS_SHA_256 = new DERObjectIdentifier(id_TA_RSA + ".4");
    public static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_1 = new DERObjectIdentifier(id_TA_RSA + ".1");
    public static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_256 = new DERObjectIdentifier(id_TA_RSA + ".2");
}
