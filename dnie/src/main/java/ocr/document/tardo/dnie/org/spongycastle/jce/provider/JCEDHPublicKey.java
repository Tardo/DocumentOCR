package org.spongycastle.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.pkcs.DHParameter;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.DHDomainParameters;
import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
import org.spongycastle.crypto.params.DHPublicKeyParameters;

public class JCEDHPublicKey implements DHPublicKey {
    static final long serialVersionUID = -216691575254424324L;
    private DHParameterSpec dhSpec;
    private SubjectPublicKeyInfo info;
    /* renamed from: y */
    private BigInteger f177y;

    JCEDHPublicKey(DHPublicKeySpec spec) {
        this.f177y = spec.getY();
        this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
    }

    JCEDHPublicKey(DHPublicKey key) {
        this.f177y = key.getY();
        this.dhSpec = key.getParams();
    }

    JCEDHPublicKey(DHPublicKeyParameters params) {
        this.f177y = params.getY();
        this.dhSpec = new DHParameterSpec(params.getParameters().getP(), params.getParameters().getG(), params.getParameters().getL());
    }

    JCEDHPublicKey(BigInteger y, DHParameterSpec dhSpec) {
        this.f177y = y;
        this.dhSpec = dhSpec;
    }

    JCEDHPublicKey(SubjectPublicKeyInfo info) {
        this.info = info;
        try {
            this.f177y = ((DERInteger) info.getPublicKey()).getValue();
            ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithmId().getParameters());
            DERObjectIdentifier id = info.getAlgorithmId().getObjectId();
            if (id.equals(PKCSObjectIdentifiers.dhKeyAgreement) || isPKCSParam(seq)) {
                DHParameter params = new DHParameter(seq);
                if (params.getL() != null) {
                    this.dhSpec = new DHParameterSpec(params.getP(), params.getG(), params.getL().intValue());
                } else {
                    this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
                }
            } else if (id.equals(X9ObjectIdentifiers.dhpublicnumber)) {
                DHDomainParameters params2 = DHDomainParameters.getInstance(seq);
                this.dhSpec = new DHParameterSpec(params2.getP().getValue(), params2.getG().getValue());
            } else {
                throw new IllegalArgumentException("unknown algorithm type: " + id);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in DH public key");
        }
    }

    public String getAlgorithm() {
        return "DH";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        if (this.info != null) {
            return this.info.getDEREncoded();
        }
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL()).getDERObject()), new DERInteger(this.f177y)).getDEREncoded();
    }

    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    public BigInteger getY() {
        return this.f177y;
    }

    private boolean isPKCSParam(ASN1Sequence seq) {
        if (seq.size() == 2) {
            return true;
        }
        if (seq.size() > 3) {
            return false;
        }
        if (DERInteger.getInstance(seq.getObjectAt(2)).getValue().compareTo(BigInteger.valueOf((long) DERInteger.getInstance(seq.getObjectAt(0)).getValue().bitLength())) > 0) {
            return false;
        }
        return true;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.f177y = (BigInteger) in.readObject();
        this.dhSpec = new DHParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject(), in.readInt());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getY());
        out.writeObject(this.dhSpec.getP());
        out.writeObject(this.dhSpec.getG());
        out.writeInt(this.dhSpec.getL());
    }
}
