package org.bouncycastle.cms;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

public class PKCS5Scheme2UTF8PBEKey extends CMSPBEKey {
    public PKCS5Scheme2UTF8PBEKey(char[] cArr, AlgorithmParameters algorithmParameters) throws InvalidAlgorithmParameterException {
        super(cArr, CMSPBEKey.getParamSpec(algorithmParameters));
    }

    public PKCS5Scheme2UTF8PBEKey(char[] cArr, byte[] bArr, int i) {
        super(cArr, bArr, i);
    }

    byte[] getEncoded(String str) {
        PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator();
        pKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(getPassword()), getSalt(), getIterationCount());
        return ((KeyParameter) pKCS5S2ParametersGenerator.generateDerivedParameters(CMSEnvelopedHelper.INSTANCE.getKeySize(str))).getKey();
    }
}
