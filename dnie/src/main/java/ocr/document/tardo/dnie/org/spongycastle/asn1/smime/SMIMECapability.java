package org.spongycastle.asn1.smime;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class SMIMECapability extends ASN1Encodable {
    public static final DERObjectIdentifier aES128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
    public static final DERObjectIdentifier aES192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
    public static final DERObjectIdentifier aES256_CBC = NISTObjectIdentifiers.id_aes256_CBC;
    public static final DERObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
    public static final DERObjectIdentifier dES_CBC = new DERObjectIdentifier("1.3.14.3.2.7");
    public static final DERObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
    public static final DERObjectIdentifier preferSignedData = PKCSObjectIdentifiers.preferSignedData;
    public static final DERObjectIdentifier rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
    public static final DERObjectIdentifier sMIMECapabilitiesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;
    private DERObjectIdentifier capabilityID;
    private DEREncodable parameters;

    public SMIMECapability(ASN1Sequence seq) {
        this.capabilityID = (DERObjectIdentifier) seq.getObjectAt(0);
        if (seq.size() > 1) {
            this.parameters = (DERObject) seq.getObjectAt(1);
        }
    }

    public SMIMECapability(DERObjectIdentifier capabilityID, DEREncodable parameters) {
        this.capabilityID = capabilityID;
        this.parameters = parameters;
    }

    public static SMIMECapability getInstance(Object obj) {
        if (obj == null || (obj instanceof SMIMECapability)) {
            return (SMIMECapability) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new SMIMECapability((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Invalid SMIMECapability");
    }

    public DERObjectIdentifier getCapabilityID() {
        return this.capabilityID;
    }

    public DEREncodable getParameters() {
        return this.parameters;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.capabilityID);
        if (this.parameters != null) {
            v.add(this.parameters);
        }
        return new DERSequence(v);
    }
}
