package org.bouncycastle.openssl.jcajce;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.util.Integers;

class PEMUtilities {
    private static final Map KEYSIZES = new HashMap();
    private static final Set PKCS5_SCHEME_1 = new HashSet();
    private static final Set PKCS5_SCHEME_2 = new HashSet();

    static {
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);
        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.id_PBES2);
        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.des_EDE3_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes128_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes192_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes256_CBC);
        KEYSIZES.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), Integers.valueOf(128));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), Integers.valueOf(256));
    }

    PEMUtilities() {
    }

    static byte[] crypt(boolean z, JcaJceHelper jcaJceHelper, byte[] bArr, char[] cArr, String str, byte[] bArr2) throws PEMException {
        String str2;
        int i = 128;
        int i2 = 1;
        boolean z2 = false;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr2);
        String str3 = "CBC";
        String str4 = "PKCS5Padding";
        if (str.endsWith("-CFB")) {
            str3 = "CFB";
            str4 = "NoPadding";
        }
        if (str.endsWith("-ECB") || "DES-EDE".equals(str) || "DES-EDE3".equals(str)) {
            str3 = "ECB";
            ivParameterSpec = null;
        }
        if (str.endsWith("-OFB")) {
            str3 = "OFB";
            str4 = "NoPadding";
        }
        String str5;
        SecretKey key;
        if (str.startsWith("DES-EDE")) {
            str5 = "DESede";
            if (!str.startsWith("DES-EDE3")) {
                z2 = true;
            }
            key = getKey(cArr, str5, 24, bArr2, z2);
            str2 = str5;
            AlgorithmParameterSpec algorithmParameterSpec = ivParameterSpec;
            Key key2 = key;
        } else if (str.startsWith("DES-")) {
            str5 = "DES";
            key = getKey(cArr, str5, 8, bArr2);
            str2 = str5;
            r5 = ivParameterSpec;
            r2 = key;
        } else if (str.startsWith("BF-")) {
            str5 = "Blowfish";
            key = getKey(cArr, str5, 16, bArr2);
            str2 = str5;
            r5 = ivParameterSpec;
            r2 = key;
        } else if (str.startsWith("RC2-")) {
            String str6 = "RC2";
            int i3 = str.startsWith("RC2-40-") ? 40 : str.startsWith("RC2-64-") ? 64 : 128;
            SecretKey key3 = getKey(cArr, str6, i3 / 8, bArr2);
            RC2ParameterSpec rC2ParameterSpec = ivParameterSpec == null ? new RC2ParameterSpec(i3) : new RC2ParameterSpec(i3, bArr2);
            str2 = str6;
            key = key3;
            r5 = rC2ParameterSpec;
            r2 = key;
        } else if (str.startsWith("AES-")) {
            String str7 = "AES";
            if (bArr2.length > 8) {
                Object obj = new byte[8];
                System.arraycopy(bArr2, 0, obj, 0, 8);
                bArr2 = obj;
            }
            if (!str.startsWith("AES-128-")) {
                if (str.startsWith("AES-192-")) {
                    i = 192;
                } else if (str.startsWith("AES-256-")) {
                    i = 256;
                } else {
                    throw new EncryptionException("unknown AES encryption with private key");
                }
            }
            SecretKey key4 = getKey(cArr, "AES", i / 8, bArr2);
            r5 = ivParameterSpec;
            r2 = key4;
            str2 = str7;
        } else {
            throw new EncryptionException("unknown encryption with private key");
        }
        try {
            Cipher createCipher = jcaJceHelper.createCipher(str2 + "/" + str3 + "/" + str4);
            if (!z) {
                i2 = 2;
            }
            if (algorithmParameterSpec == null) {
                createCipher.init(i2, key2);
            } else {
                createCipher.init(i2, key2, algorithmParameterSpec);
            }
            return createCipher.doFinal(bArr);
        } catch (Throwable e) {
            throw new EncryptionException("exception using cipher - please check password and data.", e);
        }
    }

    public static SecretKey generateSecretKeyForPKCS5Scheme2(String str, char[] cArr, byte[] bArr, int i) {
        PBEParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator();
        pKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToBytes(cArr), bArr, i);
        return new SecretKeySpec(((KeyParameter) pKCS5S2ParametersGenerator.generateDerivedParameters(getKeySize(str))).getKey(), str);
    }

    private static SecretKey getKey(char[] cArr, String str, int i, byte[] bArr) {
        return getKey(cArr, str, i, bArr, false);
    }

    private static SecretKey getKey(char[] cArr, String str, int i, byte[] bArr, boolean z) {
        OpenSSLPBEParametersGenerator openSSLPBEParametersGenerator = new OpenSSLPBEParametersGenerator();
        openSSLPBEParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToBytes(cArr), bArr);
        Object key = ((KeyParameter) openSSLPBEParametersGenerator.generateDerivedParameters(i * 8)).getKey();
        if (z && key.length >= 24) {
            System.arraycopy(key, 0, key, 16, 8);
        }
        return new SecretKeySpec(key, str);
    }

    static int getKeySize(String str) {
        if (KEYSIZES.containsKey(str)) {
            return ((Integer) KEYSIZES.get(str)).intValue();
        }
        throw new IllegalStateException("no key size for algorithm: " + str);
    }

    public static boolean isPKCS12(DERObjectIdentifier dERObjectIdentifier) {
        return dERObjectIdentifier.getId().startsWith(PKCSObjectIdentifiers.pkcs_12PbeIds.getId());
    }

    static boolean isPKCS5Scheme1(DERObjectIdentifier dERObjectIdentifier) {
        return PKCS5_SCHEME_1.contains(dERObjectIdentifier);
    }

    static boolean isPKCS5Scheme2(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return PKCS5_SCHEME_2.contains(aSN1ObjectIdentifier);
    }
}
