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
import org.spongycastle.asn1.oiw.ElGamalParameter;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.crypto.params.ElGamalPublicKeyParameters;
import org.spongycastle.jce.interfaces.ElGamalPublicKey;
import org.spongycastle.jce.spec.ElGamalParameterSpec;
import org.spongycastle.jce.spec.ElGamalPublicKeySpec;

public class JCEElGamalPublicKey implements ElGamalPublicKey, DHPublicKey {
    static final long serialVersionUID = 8712728417091216948L;
    private ElGamalParameterSpec elSpec;
    /* renamed from: y */
    private BigInteger f591y;

    JCEElGamalPublicKey(ElGamalPublicKeySpec spec) {
        this.f591y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    JCEElGamalPublicKey(DHPublicKeySpec spec) {
        this.f591y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
    }

    JCEElGamalPublicKey(ElGamalPublicKey key) {
        this.f591y = key.getY();
        this.elSpec = key.getParameters();
    }

    JCEElGamalPublicKey(DHPublicKey key) {
        this.f591y = key.getY();
        this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
    }

    JCEElGamalPublicKey(ElGamalPublicKeyParameters params) {
        this.f591y = params.getY();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    JCEElGamalPublicKey(BigInteger y, ElGamalParameterSpec elSpec) {
        this.f591y = y;
        this.elSpec = elSpec;
    }

    JCEElGamalPublicKey(SubjectPublicKeyInfo info) {
        ElGamalParameter params = new ElGamalParameter((ASN1Sequence) info.getAlgorithmId().getParameters());
        try {
            this.f591y = ((DERInteger) info.getPublicKey()).getValue();
            this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }
    }

    public String getAlgorithm() {
        return "ElGamal";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(this.elSpec.getP(), this.elSpec.getG()).getDERObject()), new DERInteger(this.f591y)).getDEREncoded();
    }

    public ElGamalParameterSpec getParameters() {
        return this.elSpec;
    }

    public DHParameterSpec getParams() {
        return new DHParameterSpec(this.elSpec.getP(), this.elSpec.getG());
    }

    public BigInteger getY() {
        return this.f591y;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.f591y = (BigInteger) in.readObject();
        this.elSpec = new ElGamalParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getY());
        out.writeObject(this.elSpec.getP());
        out.writeObject(this.elSpec.getG());
    }
}
