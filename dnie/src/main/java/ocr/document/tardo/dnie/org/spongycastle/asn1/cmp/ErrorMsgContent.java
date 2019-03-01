package org.spongycastle.asn1.cmp;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class ErrorMsgContent extends ASN1Encodable {
    private DERInteger errorCode;
    private PKIFreeText errorDetails;
    private PKIStatusInfo pkiStatusInfo;

    private ErrorMsgContent(ASN1Sequence seq) {
        Enumeration en = seq.getObjects();
        this.pkiStatusInfo = PKIStatusInfo.getInstance(en.nextElement());
        while (en.hasMoreElements()) {
            Object o = en.nextElement();
            if (o instanceof DERInteger) {
                this.errorCode = DERInteger.getInstance(o);
            } else {
                this.errorDetails = PKIFreeText.getInstance(o);
            }
        }
    }

    public static ErrorMsgContent getInstance(Object o) {
        if (o instanceof ErrorMsgContent) {
            return (ErrorMsgContent) o;
        }
        if (o instanceof ASN1Sequence) {
            return new ErrorMsgContent((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public ErrorMsgContent(PKIStatusInfo pkiStatusInfo) {
        this(pkiStatusInfo, null, null);
    }

    public ErrorMsgContent(PKIStatusInfo pkiStatusInfo, DERInteger errorCode, PKIFreeText errorDetails) {
        if (pkiStatusInfo == null) {
            throw new IllegalArgumentException("'pkiStatusInfo' cannot be null");
        }
        this.pkiStatusInfo = pkiStatusInfo;
        this.errorCode = errorCode;
        this.errorDetails = errorDetails;
    }

    public PKIStatusInfo getPKIStatusInfo() {
        return this.pkiStatusInfo;
    }

    public DERInteger getErrorCode() {
        return this.errorCode;
    }

    public PKIFreeText getErrorDetails() {
        return this.errorDetails;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.pkiStatusInfo);
        addOptional(v, this.errorCode);
        addOptional(v, this.errorDetails);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
        if (obj != null) {
            v.add(obj);
        }
    }
}
