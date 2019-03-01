package org.spongycastle.asn1.cmp;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class PKIStatusInfo extends ASN1Encodable {
    DERBitString failInfo;
    DERInteger status;
    PKIFreeText statusString;

    public static PKIStatusInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIStatusInfo getInstance(Object obj) {
        if (obj instanceof PKIStatusInfo) {
            return (PKIStatusInfo) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PKIStatusInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public PKIStatusInfo(ASN1Sequence seq) {
        this.status = DERInteger.getInstance(seq.getObjectAt(0));
        this.statusString = null;
        this.failInfo = null;
        if (seq.size() > 2) {
            this.statusString = PKIFreeText.getInstance(seq.getObjectAt(1));
            this.failInfo = DERBitString.getInstance(seq.getObjectAt(2));
        } else if (seq.size() > 1) {
            DEREncodable obj = seq.getObjectAt(1);
            if (obj instanceof DERBitString) {
                this.failInfo = DERBitString.getInstance(obj);
            } else {
                this.statusString = PKIFreeText.getInstance(obj);
            }
        }
    }

    public PKIStatusInfo(int status) {
        this.status = new DERInteger(status);
    }

    public PKIStatusInfo(PKIStatus status) {
        this.status = DERInteger.getInstance(status.toASN1Object());
    }

    public PKIStatusInfo(int status, PKIFreeText statusString) {
        this.status = new DERInteger(status);
        this.statusString = statusString;
    }

    public PKIStatusInfo(PKIStatus status, PKIFreeText statusString) {
        this.status = DERInteger.getInstance(status.toASN1Object());
        this.statusString = statusString;
    }

    public PKIStatusInfo(int status, PKIFreeText statusString, PKIFailureInfo failInfo) {
        this.status = new DERInteger(status);
        this.statusString = statusString;
        this.failInfo = failInfo;
    }

    public BigInteger getStatus() {
        return this.status.getValue();
    }

    public PKIFreeText getStatusString() {
        return this.statusString;
    }

    public DERBitString getFailInfo() {
        return this.failInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.status);
        if (this.statusString != null) {
            v.add(this.statusString);
        }
        if (this.failInfo != null) {
            v.add(this.failInfo);
        }
        return new DERSequence(v);
    }
}
