package org.spongycastle.jce.provider;

import java.io.IOException;
import java.math.BigInteger;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.crypto.params.GOST3410PublicKeyParameters;
import org.spongycastle.jce.interfaces.GOST3410Params;
import org.spongycastle.jce.interfaces.GOST3410PublicKey;
import org.spongycastle.jce.spec.GOST3410ParameterSpec;
import org.spongycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;
import org.spongycastle.jce.spec.GOST3410PublicKeySpec;

public class JDKGOST3410PublicKey implements GOST3410PublicKey {
    private GOST3410Params gost3410Spec;
    /* renamed from: y */
    private BigInteger f593y;

    JDKGOST3410PublicKey(GOST3410PublicKeySpec spec) {
        this.f593y = spec.getY();
        this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
    }

    JDKGOST3410PublicKey(GOST3410PublicKey key) {
        this.f593y = key.getY();
        this.gost3410Spec = key.getParameters();
    }

    JDKGOST3410PublicKey(GOST3410PublicKeyParameters params, GOST3410ParameterSpec spec) {
        this.f593y = params.getY();
        this.gost3410Spec = spec;
    }

    JDKGOST3410PublicKey(BigInteger y, GOST3410ParameterSpec gost3410Spec) {
        this.f593y = y;
        this.gost3410Spec = gost3410Spec;
    }

    JDKGOST3410PublicKey(SubjectPublicKeyInfo info) {
        GOST3410PublicKeyAlgParameters params = new GOST3410PublicKeyAlgParameters((ASN1Sequence) info.getAlgorithmId().getParameters());
        try {
            byte[] keyEnc = ((DEROctetString) info.getPublicKey()).getOctets();
            byte[] keyBytes = new byte[keyEnc.length];
            for (int i = 0; i != keyEnc.length; i++) {
                keyBytes[i] = keyEnc[(keyEnc.length - 1) - i];
            }
            this.f593y = new BigInteger(1, keyBytes);
            this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(params);
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in GOST3410 public key");
        }
    }

    public String getAlgorithm() {
        return "GOST3410";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        byte[] keyBytes;
        SubjectPublicKeyInfo info;
        byte[] keyEnc = getY().toByteArray();
        if (keyEnc[0] == (byte) 0) {
            keyBytes = new byte[(keyEnc.length - 1)];
        } else {
            keyBytes = new byte[keyEnc.length];
        }
        for (int i = 0; i != keyBytes.length; i++) {
            keyBytes[i] = keyEnc[(keyEnc.length - 1) - i];
        }
        if (!(this.gost3410Spec instanceof GOST3410ParameterSpec)) {
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(keyBytes));
        } else if (this.gost3410Spec.getEncryptionParamSetOID() != null) {
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new DERObjectIdentifier(this.gost3410Spec.getPublicKeyParamSetOID()), new DERObjectIdentifier(this.gost3410Spec.getDigestParamSetOID()), new DERObjectIdentifier(this.gost3410Spec.getEncryptionParamSetOID())).getDERObject()), new DEROctetString(keyBytes));
        } else {
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new DERObjectIdentifier(this.gost3410Spec.getPublicKeyParamSetOID()), new DERObjectIdentifier(this.gost3410Spec.getDigestParamSetOID())).getDERObject()), new DEROctetString(keyBytes));
        }
        return info.getDEREncoded();
    }

    public GOST3410Params getParameters() {
        return this.gost3410Spec;
    }

    public BigInteger getY() {
        return this.f593y;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("GOST3410 Public Key").append(nl);
        buf.append("            y: ").append(getY().toString(16)).append(nl);
        return buf.toString();
    }

    public boolean equals(Object o) {
        if (!(o instanceof JDKGOST3410PublicKey)) {
            return false;
        }
        JDKGOST3410PublicKey other = (JDKGOST3410PublicKey) o;
        if (this.f593y.equals(other.f593y) && this.gost3410Spec.equals(other.gost3410Spec)) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.f593y.hashCode() ^ this.gost3410Spec.hashCode();
    }
}
