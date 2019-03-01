package org.spongycastle.asn1.cms;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class CompressedData extends ASN1Encodable {
    private AlgorithmIdentifier compressionAlgorithm;
    private ContentInfo encapContentInfo;
    private DERInteger version;

    public CompressedData(AlgorithmIdentifier compressionAlgorithm, ContentInfo encapContentInfo) {
        this.version = new DERInteger(0);
        this.compressionAlgorithm = compressionAlgorithm;
        this.encapContentInfo = encapContentInfo;
    }

    public CompressedData(ASN1Sequence seq) {
        this.version = (DERInteger) seq.getObjectAt(0);
        this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
    }

    public static CompressedData getInstance(ASN1TaggedObject _ato, boolean _explicit) {
        return getInstance(ASN1Sequence.getInstance(_ato, _explicit));
    }

    public static CompressedData getInstance(Object _obj) {
        if (_obj == null || (_obj instanceof CompressedData)) {
            return (CompressedData) _obj;
        }
        if (_obj instanceof ASN1Sequence) {
            return new CompressedData((ASN1Sequence) _obj);
        }
        throw new IllegalArgumentException("Invalid CompressedData: " + _obj.getClass().getName());
    }

    public DERInteger getVersion() {
        return this.version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier() {
        return this.compressionAlgorithm;
    }

    public ContentInfo getEncapContentInfo() {
        return this.encapContentInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.compressionAlgorithm);
        v.add(this.encapContentInfo);
        return new BERSequence(v);
    }
}
