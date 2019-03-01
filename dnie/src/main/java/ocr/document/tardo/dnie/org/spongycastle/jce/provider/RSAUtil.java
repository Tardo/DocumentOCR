package org.spongycastle.jce.provider;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;

class RSAUtil {
    RSAUtil() {
    }

    static boolean isRsaOid(DERObjectIdentifier algOid) {
        return algOid.equals(PKCSObjectIdentifiers.rsaEncryption) || algOid.equals(X509ObjectIdentifiers.id_ea_rsa) || algOid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS) || algOid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP);
    }

    static RSAKeyParameters generatePublicKeyParameter(RSAPublicKey key) {
        return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());
    }

    static RSAKeyParameters generatePrivateKeyParameter(RSAPrivateKey key) {
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;
            return new RSAPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
        }
        RSAPrivateKey k2 = key;
        return new RSAKeyParameters(true, k2.getModulus(), k2.getPrivateExponent());
    }
}
