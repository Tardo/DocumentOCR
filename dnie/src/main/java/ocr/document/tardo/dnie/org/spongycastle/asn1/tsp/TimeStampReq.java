package org.spongycastle.asn1.tsp;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.X509Extensions;

public class TimeStampReq extends ASN1Encodable {
    DERBoolean certReq;
    X509Extensions extensions;
    MessageImprint messageImprint;
    DERInteger nonce;
    DERObjectIdentifier tsaPolicy;
    DERInteger version;

    public static TimeStampReq getInstance(Object o) {
        if (o == null || (o instanceof TimeStampReq)) {
            return (TimeStampReq) o;
        }
        if (o instanceof ASN1Sequence) {
            return new TimeStampReq((ASN1Sequence) o);
        }
        throw new IllegalArgumentException("Unknown object in 'TimeStampReq' factory : " + o.getClass().getName() + ".");
    }

    public TimeStampReq(ASN1Sequence seq) {
        int nbObjects = seq.size();
        this.version = DERInteger.getInstance(seq.getObjectAt(0));
        int seqStart = 0 + 1;
        this.messageImprint = MessageImprint.getInstance(seq.getObjectAt(seqStart));
        for (int opt = seqStart + 1; opt < nbObjects; opt++) {
            if (seq.getObjectAt(opt) instanceof DERObjectIdentifier) {
                this.tsaPolicy = DERObjectIdentifier.getInstance(seq.getObjectAt(opt));
            } else if (seq.getObjectAt(opt) instanceof DERInteger) {
                this.nonce = DERInteger.getInstance(seq.getObjectAt(opt));
            } else if (seq.getObjectAt(opt) instanceof DERBoolean) {
                this.certReq = DERBoolean.getInstance(seq.getObjectAt(opt));
            } else if (seq.getObjectAt(opt) instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(opt);
                if (tagged.getTagNo() == 0) {
                    this.extensions = X509Extensions.getInstance(tagged, false);
                }
            }
        }
    }

    public TimeStampReq(MessageImprint messageImprint, DERObjectIdentifier tsaPolicy, DERInteger nonce, DERBoolean certReq, X509Extensions extensions) {
        this.version = new DERInteger(1);
        this.messageImprint = messageImprint;
        this.tsaPolicy = tsaPolicy;
        this.nonce = nonce;
        this.certReq = certReq;
        this.extensions = extensions;
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public DERObjectIdentifier getReqPolicy() {
        return this.tsaPolicy;
    }

    public DERInteger getNonce() {
        return this.nonce;
    }

    public DERBoolean getCertReq() {
        return this.certReq;
    }

    public X509Extensions getExtensions() {
        return this.extensions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.messageImprint);
        if (this.tsaPolicy != null) {
            v.add(this.tsaPolicy);
        }
        if (this.nonce != null) {
            v.add(this.nonce);
        }
        if (this.certReq != null && this.certReq.isTrue()) {
            v.add(this.certReq);
        }
        if (this.extensions != null) {
            v.add(new DERTaggedObject(false, 0, this.extensions));
        }
        return new DERSequence(v);
    }
}
