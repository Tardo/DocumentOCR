package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.McEliecePublicKey;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.McEliecePublicKeySpec;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class BCMcEliecePublicKey implements CipherParameters, PublicKey {
    private static final long serialVersionUID = 1;
    private McElieceParameters McElieceParams;
    /* renamed from: g */
    private GF2Matrix f342g;
    /* renamed from: n */
    private int f343n;
    private String oid;
    /* renamed from: t */
    private int f344t;

    public BCMcEliecePublicKey(String str, int i, int i2, GF2Matrix gF2Matrix) {
        this.oid = str;
        this.f343n = i;
        this.f344t = i2;
        this.f342g = gF2Matrix;
    }

    public BCMcEliecePublicKey(McEliecePublicKeyParameters mcEliecePublicKeyParameters) {
        this(mcEliecePublicKeyParameters.getOIDString(), mcEliecePublicKeyParameters.getN(), mcEliecePublicKeyParameters.getT(), mcEliecePublicKeyParameters.getG());
        this.McElieceParams = mcEliecePublicKeyParameters.getParameters();
    }

    public BCMcEliecePublicKey(McEliecePublicKeySpec mcEliecePublicKeySpec) {
        this(mcEliecePublicKeySpec.getOIDString(), mcEliecePublicKeySpec.getN(), mcEliecePublicKeySpec.getT(), mcEliecePublicKeySpec.getG());
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof BCMcEliecePublicKey)) {
            return false;
        }
        BCMcEliecePublicKey bCMcEliecePublicKey = (BCMcEliecePublicKey) obj;
        return this.f343n == bCMcEliecePublicKey.f343n && this.f344t == bCMcEliecePublicKey.f344t && this.f342g.equals(bCMcEliecePublicKey.f342g);
    }

    protected ASN1Primitive getAlgParams() {
        return null;
    }

    public String getAlgorithm() {
        return "McEliece";
    }

    public byte[] getEncoded() {
        try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(getOID(), DERNull.INSTANCE), new McEliecePublicKey(new ASN1ObjectIdentifier(this.oid), this.f343n, this.f344t, this.f342g)).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return null;
    }

    public GF2Matrix getG() {
        return this.f342g;
    }

    public int getK() {
        return this.f342g.getNumRows();
    }

    public McElieceParameters getMcElieceParameters() {
        return this.McElieceParams;
    }

    public int getN() {
        return this.f343n;
    }

    protected ASN1ObjectIdentifier getOID() {
        return new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");
    }

    public String getOIDString() {
        return this.oid;
    }

    public int getT() {
        return this.f344t;
    }

    public int hashCode() {
        return (this.f343n + this.f344t) + this.f342g.hashCode();
    }

    public String toString() {
        return (("McEliecePublicKey:\n" + " length of the code         : " + this.f343n + "\n") + " error correction capability: " + this.f344t + "\n") + " generator matrix           : " + this.f342g.toString();
    }
}
