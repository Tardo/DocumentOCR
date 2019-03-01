package org.spongycastle.asn1.x509.qualified;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class BiometricData extends ASN1Encodable {
    ASN1OctetString biometricDataHash;
    AlgorithmIdentifier hashAlgorithm;
    DERIA5String sourceDataUri;
    TypeOfBiometricData typeOfBiometricData;

    public static BiometricData getInstance(Object obj) {
        if (obj == null || (obj instanceof BiometricData)) {
            return (BiometricData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new BiometricData(ASN1Sequence.getInstance(obj));
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public BiometricData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.typeOfBiometricData = TypeOfBiometricData.getInstance(e.nextElement());
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
        this.biometricDataHash = ASN1OctetString.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            this.sourceDataUri = DERIA5String.getInstance(e.nextElement());
        }
    }

    public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm, ASN1OctetString biometricDataHash, DERIA5String sourceDataUri) {
        this.typeOfBiometricData = typeOfBiometricData;
        this.hashAlgorithm = hashAlgorithm;
        this.biometricDataHash = biometricDataHash;
        this.sourceDataUri = sourceDataUri;
    }

    public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm, ASN1OctetString biometricDataHash) {
        this.typeOfBiometricData = typeOfBiometricData;
        this.hashAlgorithm = hashAlgorithm;
        this.biometricDataHash = biometricDataHash;
        this.sourceDataUri = null;
    }

    public TypeOfBiometricData getTypeOfBiometricData() {
        return this.typeOfBiometricData;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getBiometricDataHash() {
        return this.biometricDataHash;
    }

    public DERIA5String getSourceDataUri() {
        return this.sourceDataUri;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.typeOfBiometricData);
        seq.add(this.hashAlgorithm);
        seq.add(this.biometricDataHash);
        if (this.sourceDataUri != null) {
            seq.add(this.sourceDataUri);
        }
        return new DERSequence(seq);
    }
}
