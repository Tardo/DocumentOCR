package org.spongycastle.asn1.icao;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class LDSSecurityObject extends ASN1Encodable implements ICAOObjectIdentifiers {
    public static final int ub_DataGroups = 16;
    private DataGroupHash[] datagroupHash;
    private AlgorithmIdentifier digestAlgorithmIdentifier;
    private DERInteger version;
    private LDSVersionInfo versionInfo;

    public static LDSSecurityObject getInstance(Object obj) {
        if (obj instanceof LDSSecurityObject) {
            return (LDSSecurityObject) obj;
        }
        if (obj != null) {
            return new LDSSecurityObject(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private LDSSecurityObject(ASN1Sequence seq) {
        this.version = new DERInteger(0);
        if (seq == null || seq.size() == 0) {
            throw new IllegalArgumentException("null or empty sequence passed.");
        }
        Enumeration e = seq.getObjects();
        this.version = DERInteger.getInstance(e.nextElement());
        this.digestAlgorithmIdentifier = AlgorithmIdentifier.getInstance(e.nextElement());
        ASN1Sequence datagroupHashSeq = ASN1Sequence.getInstance(e.nextElement());
        if (this.version.getValue().intValue() == 1) {
            this.versionInfo = LDSVersionInfo.getInstance(e.nextElement());
        }
        checkDatagroupHashSeqSize(datagroupHashSeq.size());
        this.datagroupHash = new DataGroupHash[datagroupHashSeq.size()];
        for (int i = 0; i < datagroupHashSeq.size(); i++) {
            this.datagroupHash[i] = DataGroupHash.getInstance(datagroupHashSeq.getObjectAt(i));
        }
    }

    public LDSSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash) {
        this.version = new DERInteger(0);
        this.version = new DERInteger(0);
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
        this.datagroupHash = datagroupHash;
        checkDatagroupHashSeqSize(datagroupHash.length);
    }

    public LDSSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash, LDSVersionInfo versionInfo) {
        this.version = new DERInteger(0);
        this.version = new DERInteger(1);
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
        this.datagroupHash = datagroupHash;
        this.versionInfo = versionInfo;
        checkDatagroupHashSeqSize(datagroupHash.length);
    }

    private void checkDatagroupHashSeqSize(int size) {
        if (size < 2 || size > 16) {
            throw new IllegalArgumentException("wrong size in DataGroupHashValues : not in (2..16)");
        }
    }

    public int getVersion() {
        return this.version.getValue().intValue();
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
        return this.digestAlgorithmIdentifier;
    }

    public DataGroupHash[] getDatagroupHash() {
        return this.datagroupHash;
    }

    public LDSVersionInfo getVersionInfo() {
        return this.versionInfo;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.version);
        seq.add(this.digestAlgorithmIdentifier);
        ASN1EncodableVector seqname = new ASN1EncodableVector();
        for (DEREncodable add : this.datagroupHash) {
            seqname.add(add);
        }
        seq.add(new DERSequence(seqname));
        if (this.versionInfo != null) {
            seq.add(this.versionInfo);
        }
        return new DERSequence(seq);
    }
}
