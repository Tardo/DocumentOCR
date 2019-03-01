package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;

public class AlgorithmIdentifier extends ASN1Encodable {
    private DERObjectIdentifier objectId;
    private DEREncodable parameters;
    private boolean parametersDefined;

    public static AlgorithmIdentifier getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AlgorithmIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof AlgorithmIdentifier)) {
            return (AlgorithmIdentifier) obj;
        }
        if (obj instanceof DERObjectIdentifier) {
            return new AlgorithmIdentifier((DERObjectIdentifier) obj);
        }
        if (obj instanceof String) {
            return new AlgorithmIdentifier((String) obj);
        }
        if (obj instanceof ASN1Sequence) {
            return new AlgorithmIdentifier((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public AlgorithmIdentifier(DERObjectIdentifier objectId) {
        this.parametersDefined = false;
        this.objectId = objectId;
    }

    public AlgorithmIdentifier(String objectId) {
        this.parametersDefined = false;
        this.objectId = new DERObjectIdentifier(objectId);
    }

    public AlgorithmIdentifier(DERObjectIdentifier objectId, DEREncodable parameters) {
        this.parametersDefined = false;
        this.parametersDefined = true;
        this.objectId = objectId;
        this.parameters = parameters;
    }

    public AlgorithmIdentifier(ASN1Sequence seq) {
        this.parametersDefined = false;
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.objectId = DERObjectIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.parametersDefined = true;
            this.parameters = seq.getObjectAt(1);
            return;
        }
        this.parameters = null;
    }

    public ASN1ObjectIdentifier getAlgorithm() {
        return new ASN1ObjectIdentifier(this.objectId.getId());
    }

    public DERObjectIdentifier getObjectId() {
        return this.objectId;
    }

    public DEREncodable getParameters() {
        return this.parameters;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.objectId);
        if (this.parametersDefined) {
            if (this.parameters != null) {
                v.add(this.parameters);
            } else {
                v.add(DERNull.INSTANCE);
            }
        }
        return new DERSequence(v);
    }
}
