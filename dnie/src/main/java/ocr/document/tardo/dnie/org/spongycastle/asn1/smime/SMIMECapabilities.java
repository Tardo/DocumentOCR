package org.spongycastle.asn1.smime;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class SMIMECapabilities extends ASN1Encodable {
    public static final DERObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
    public static final DERObjectIdentifier dES_CBC = new DERObjectIdentifier("1.3.14.3.2.7");
    public static final DERObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
    public static final DERObjectIdentifier preferSignedData = PKCSObjectIdentifiers.preferSignedData;
    public static final DERObjectIdentifier rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
    public static final DERObjectIdentifier sMIMECapabilitesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;
    private ASN1Sequence capabilities;

    public static SMIMECapabilities getInstance(Object o) {
        if (o == null || (o instanceof SMIMECapabilities)) {
            return (SMIMECapabilities) o;
        }
        if (o instanceof ASN1Sequence) {
            return new SMIMECapabilities((ASN1Sequence) o);
        }
        if (o instanceof Attribute) {
            return new SMIMECapabilities((ASN1Sequence) ((Attribute) o).getAttrValues().getObjectAt(0));
        }
        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public SMIMECapabilities(ASN1Sequence seq) {
        this.capabilities = seq;
    }

    public Vector getCapabilities(DERObjectIdentifier capability) {
        Enumeration e = this.capabilities.getObjects();
        Vector list = new Vector();
        if (capability == null) {
            while (e.hasMoreElements()) {
                list.addElement(SMIMECapability.getInstance(e.nextElement()));
            }
        } else {
            while (e.hasMoreElements()) {
                SMIMECapability cap = SMIMECapability.getInstance(e.nextElement());
                if (capability.equals(cap.getCapabilityID())) {
                    list.addElement(cap);
                }
            }
        }
        return list;
    }

    public DERObject toASN1Object() {
        return this.capabilities;
    }
}
