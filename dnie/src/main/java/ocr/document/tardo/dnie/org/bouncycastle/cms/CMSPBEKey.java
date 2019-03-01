package org.bouncycastle.cms;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

public abstract class CMSPBEKey implements PBEKey {
    private int iterationCount;
    private char[] password;
    private byte[] salt;

    public CMSPBEKey(char[] cArr, PBEParameterSpec pBEParameterSpec) {
        this(cArr, pBEParameterSpec.getSalt(), pBEParameterSpec.getIterationCount());
    }

    public CMSPBEKey(char[] cArr, byte[] bArr, int i) {
        this.password = cArr;
        this.salt = bArr;
        this.iterationCount = i;
    }

    protected static PBEParameterSpec getParamSpec(AlgorithmParameters algorithmParameters) throws InvalidAlgorithmParameterException {
        try {
            return (PBEParameterSpec) algorithmParameters.getParameterSpec(PBEParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("cannot process PBE spec: " + e.getMessage());
        }
    }

    public String getAlgorithm() {
        return "PKCS5S2";
    }

    public byte[] getEncoded() {
        return null;
    }

    abstract byte[] getEncoded(String str);

    public String getFormat() {
        return "RAW";
    }

    public int getIterationCount() {
        return this.iterationCount;
    }

    public char[] getPassword() {
        return this.password;
    }

    public byte[] getSalt() {
        return this.salt;
    }
}
