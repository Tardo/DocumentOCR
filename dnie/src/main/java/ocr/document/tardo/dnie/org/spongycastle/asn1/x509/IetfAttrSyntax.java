package org.spongycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTF8String;

public class IetfAttrSyntax extends ASN1Encodable {
    public static final int VALUE_OCTETS = 1;
    public static final int VALUE_OID = 2;
    public static final int VALUE_UTF8 = 3;
    GeneralNames policyAuthority = null;
    int valueChoice = -1;
    Vector values = new Vector();

    public IetfAttrSyntax(ASN1Sequence seq) {
        int i = 0;
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject) {
            this.policyAuthority = GeneralNames.getInstance((ASN1TaggedObject) seq.getObjectAt(0), false);
            i = 0 + 1;
        } else if (seq.size() == 2) {
            this.policyAuthority = GeneralNames.getInstance(seq.getObjectAt(0));
            i = 0 + 1;
        }
        if (seq.getObjectAt(i) instanceof ASN1Sequence) {
            Enumeration e = ((ASN1Sequence) seq.getObjectAt(i)).getObjects();
            while (e.hasMoreElements()) {
                int type;
                DERObject obj = (DERObject) e.nextElement();
                if (obj instanceof DERObjectIdentifier) {
                    type = 2;
                } else if (obj instanceof DERUTF8String) {
                    type = 3;
                } else if (obj instanceof DEROctetString) {
                    type = 1;
                } else {
                    throw new IllegalArgumentException("Bad value type encoding IetfAttrSyntax");
                }
                if (this.valueChoice < 0) {
                    this.valueChoice = type;
                }
                if (type != this.valueChoice) {
                    throw new IllegalArgumentException("Mix of value types in IetfAttrSyntax");
                }
                this.values.addElement(obj);
            }
            return;
        }
        throw new IllegalArgumentException("Non-IetfAttrSyntax encoding");
    }

    public GeneralNames getPolicyAuthority() {
        return this.policyAuthority;
    }

    public int getValueType() {
        return this.valueChoice;
    }

    public Object[] getValues() {
        DERUTF8String[] tmp;
        int i;
        if (getValueType() == 1) {
            tmp = new ASN1OctetString[this.values.size()];
            for (i = 0; i != tmp.length; i++) {
                tmp[i] = (ASN1OctetString) this.values.elementAt(i);
            }
        } else if (getValueType() == 2) {
            tmp = new DERObjectIdentifier[this.values.size()];
            for (i = 0; i != tmp.length; i++) {
                tmp[i] = (DERObjectIdentifier) this.values.elementAt(i);
            }
        } else {
            tmp = new DERUTF8String[this.values.size()];
            for (i = 0; i != tmp.length; i++) {
                tmp[i] = (DERUTF8String) this.values.elementAt(i);
            }
        }
        return tmp;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.policyAuthority != null) {
            v.add(new DERTaggedObject(0, this.policyAuthority));
        }
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        Enumeration i = this.values.elements();
        while (i.hasMoreElements()) {
            v2.add((ASN1Encodable) i.nextElement());
        }
        v.add(new DERSequence(v2));
        return new DERSequence(v);
    }
}
