package org.spongycastle.asn1.pkcs;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

public class RSAESOAEPparams extends ASN1Encodable {
    public static final AlgorithmIdentifier DEFAULT_HASH_ALGORITHM = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, new DERNull());
    public static final AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, DEFAULT_HASH_ALGORITHM);
    public static final AlgorithmIdentifier DEFAULT_P_SOURCE_ALGORITHM = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]));
    private AlgorithmIdentifier hashAlgorithm;
    private AlgorithmIdentifier maskGenAlgorithm;
    private AlgorithmIdentifier pSourceAlgorithm;

    public static RSAESOAEPparams getInstance(Object obj) {
        if (obj instanceof RSAESOAEPparams) {
            return (RSAESOAEPparams) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new RSAESOAEPparams((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public RSAESOAEPparams() {
        this.hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        this.maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        this.pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
    }

    public RSAESOAEPparams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm, AlgorithmIdentifier pSourceAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.maskGenAlgorithm = maskGenAlgorithm;
        this.pSourceAlgorithm = pSourceAlgorithm;
    }

    public RSAESOAEPparams(ASN1Sequence seq) {
        this.hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        this.maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        this.pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject o = (ASN1TaggedObject) seq.getObjectAt(i);
            switch (o.getTagNo()) {
                case 0:
                    this.hashAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                    break;
                case 1:
                    this.maskGenAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                    break;
                case 2:
                    this.pSourceAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag");
            }
        }
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public AlgorithmIdentifier getMaskGenAlgorithm() {
        return this.maskGenAlgorithm;
    }

    public AlgorithmIdentifier getPSourceAlgorithm() {
        return this.pSourceAlgorithm;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (!this.hashAlgorithm.equals(DEFAULT_HASH_ALGORITHM)) {
            v.add(new DERTaggedObject(true, 0, this.hashAlgorithm));
        }
        if (!this.maskGenAlgorithm.equals(DEFAULT_MASK_GEN_FUNCTION)) {
            v.add(new DERTaggedObject(true, 1, this.maskGenAlgorithm));
        }
        if (!this.pSourceAlgorithm.equals(DEFAULT_P_SOURCE_ALGORITHM)) {
            v.add(new DERTaggedObject(true, 2, this.pSourceAlgorithm));
        }
        return new DERSequence(v);
    }
}