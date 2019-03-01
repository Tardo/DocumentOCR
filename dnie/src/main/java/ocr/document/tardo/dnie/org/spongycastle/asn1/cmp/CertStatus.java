package org.spongycastle.asn1.cmp;

import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

public class CertStatus extends ASN1Encodable {
    private ASN1OctetString certHash;
    private DERInteger certReqId;
    private PKIStatusInfo statusInfo;

    private CertStatus(ASN1Sequence seq) {
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        this.certReqId = DERInteger.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            this.statusInfo = PKIStatusInfo.getInstance(seq.getObjectAt(2));
        }
    }

    public CertStatus(byte[] certHash, BigInteger certReqId) {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new DERInteger(certReqId);
    }

    public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo) {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new DERInteger(certReqId);
        this.statusInfo = statusInfo;
    }

    public static CertStatus getInstance(Object o) {
        if (o instanceof CertStatus) {
            return (CertStatus) o;
        }
        if (o instanceof ASN1Sequence) {
            return new CertStatus((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public ASN1OctetString getCertHash() {
        return this.certHash;
    }

    public DERInteger getCertReqId() {
        return this.certReqId;
    }

    public PKIStatusInfo getStatusInfo() {
        return this.statusInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.certHash);
        v.add(this.certReqId);
        if (this.statusInfo != null) {
            v.add(this.statusInfo);
        }
        return new DERSequence(v);
    }
}
