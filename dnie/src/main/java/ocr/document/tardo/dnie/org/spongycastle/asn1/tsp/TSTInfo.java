package org.spongycastle.asn1.tsp;

import java.io.IOException;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.X509Extensions;

public class TSTInfo extends ASN1Encodable {
    Accuracy accuracy;
    X509Extensions extensions;
    DERGeneralizedTime genTime;
    MessageImprint messageImprint;
    DERInteger nonce;
    DERBoolean ordering;
    DERInteger serialNumber;
    GeneralName tsa;
    DERObjectIdentifier tsaPolicyId;
    DERInteger version;

    public static TSTInfo getInstance(Object o) {
        if (o == null || (o instanceof TSTInfo)) {
            return (TSTInfo) o;
        }
        if (o instanceof ASN1Sequence) {
            return new TSTInfo((ASN1Sequence) o);
        }
        if (o instanceof ASN1OctetString) {
            try {
                return getInstance(new ASN1InputStream(((ASN1OctetString) o).getOctets()).readObject());
            } catch (IOException e) {
                throw new IllegalArgumentException("Bad object format in 'TSTInfo' factory.");
            }
        }
        throw new IllegalArgumentException("Unknown object in 'TSTInfo' factory : " + o.getClass().getName() + ".");
    }

    public TSTInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.version = DERInteger.getInstance(e.nextElement());
        this.tsaPolicyId = DERObjectIdentifier.getInstance(e.nextElement());
        this.messageImprint = MessageImprint.getInstance(e.nextElement());
        this.serialNumber = DERInteger.getInstance(e.nextElement());
        this.genTime = DERGeneralizedTime.getInstance(e.nextElement());
        this.ordering = new DERBoolean(false);
        while (e.hasMoreElements()) {
            Object o = (DERObject) e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                DERTaggedObject tagged = (DERTaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        this.tsa = GeneralName.getInstance(tagged, true);
                        break;
                    case 1:
                        this.extensions = X509Extensions.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown tag value " + tagged.getTagNo());
                }
            } else if (o instanceof DERSequence) {
                this.accuracy = Accuracy.getInstance(o);
            } else if (o instanceof DERBoolean) {
                this.ordering = DERBoolean.getInstance(o);
            } else if (o instanceof DERInteger) {
                this.nonce = DERInteger.getInstance(o);
            }
        }
    }

    public TSTInfo(DERObjectIdentifier tsaPolicyId, MessageImprint messageImprint, DERInteger serialNumber, DERGeneralizedTime genTime, Accuracy accuracy, DERBoolean ordering, DERInteger nonce, GeneralName tsa, X509Extensions extensions) {
        this.version = new DERInteger(1);
        this.tsaPolicyId = tsaPolicyId;
        this.messageImprint = messageImprint;
        this.serialNumber = serialNumber;
        this.genTime = genTime;
        this.accuracy = accuracy;
        this.ordering = ordering;
        this.nonce = nonce;
        this.tsa = tsa;
        this.extensions = extensions;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public DERObjectIdentifier getPolicy() {
        return this.tsaPolicyId;
    }

    public DERInteger getSerialNumber() {
        return this.serialNumber;
    }

    public Accuracy getAccuracy() {
        return this.accuracy;
    }

    public DERGeneralizedTime getGenTime() {
        return this.genTime;
    }

    public DERBoolean getOrdering() {
        return this.ordering;
    }

    public DERInteger getNonce() {
        return this.nonce;
    }

    public GeneralName getTsa() {
        return this.tsa;
    }

    public X509Extensions getExtensions() {
        return this.extensions;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.version);
        seq.add(this.tsaPolicyId);
        seq.add(this.messageImprint);
        seq.add(this.serialNumber);
        seq.add(this.genTime);
        if (this.accuracy != null) {
            seq.add(this.accuracy);
        }
        if (this.ordering != null && this.ordering.isTrue()) {
            seq.add(this.ordering);
        }
        if (this.nonce != null) {
            seq.add(this.nonce);
        }
        if (this.tsa != null) {
            seq.add(new DERTaggedObject(true, 0, this.tsa));
        }
        if (this.extensions != null) {
            seq.add(new DERTaggedObject(false, 1, this.extensions));
        }
        return new DERSequence(seq);
    }
}
