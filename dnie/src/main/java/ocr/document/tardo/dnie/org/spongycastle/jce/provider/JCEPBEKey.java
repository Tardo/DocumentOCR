package org.spongycastle.jce.provider;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

public class JCEPBEKey implements PBEKey {
    String algorithm;
    int digest;
    int ivSize;
    int keySize;
    DERObjectIdentifier oid;
    CipherParameters param;
    PBEKeySpec pbeKeySpec;
    boolean tryWrong = false;
    int type;

    public JCEPBEKey(String algorithm, DERObjectIdentifier oid, int type, int digest, int keySize, int ivSize, PBEKeySpec pbeKeySpec, CipherParameters param) {
        this.algorithm = algorithm;
        this.oid = oid;
        this.type = type;
        this.digest = digest;
        this.keySize = keySize;
        this.ivSize = ivSize;
        this.pbeKeySpec = pbeKeySpec;
        this.param = param;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        if (this.param != null) {
            KeyParameter kParam;
            if (this.param instanceof ParametersWithIV) {
                kParam = (KeyParameter) ((ParametersWithIV) this.param).getParameters();
            } else {
                kParam = (KeyParameter) this.param;
            }
            return kParam.getKey();
        } else if (this.type == 2) {
            return PBEParametersGenerator.PKCS12PasswordToBytes(this.pbeKeySpec.getPassword());
        } else {
            return PBEParametersGenerator.PKCS5PasswordToBytes(this.pbeKeySpec.getPassword());
        }
    }

    int getType() {
        return this.type;
    }

    int getDigest() {
        return this.digest;
    }

    int getKeySize() {
        return this.keySize;
    }

    int getIvSize() {
        return this.ivSize;
    }

    CipherParameters getParam() {
        return this.param;
    }

    public char[] getPassword() {
        return this.pbeKeySpec.getPassword();
    }

    public byte[] getSalt() {
        return this.pbeKeySpec.getSalt();
    }

    public int getIterationCount() {
        return this.pbeKeySpec.getIterationCount();
    }

    public DERObjectIdentifier getOID() {
        return this.oid;
    }

    void setTryWrongPKCS12Zero(boolean tryWrong) {
        this.tryWrong = tryWrong;
    }

    boolean shouldTryWrongPKCS12() {
        return this.tryWrong;
    }
}
