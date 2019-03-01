package org.spongycastle.jce.provider.asymmetric.ec;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X962NamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.JCEECPublicKey;
import org.spongycastle.jce.provider.ProviderUtil;
import org.spongycastle.jce.spec.ECParameterSpec;

public class ECUtil {
    static int[] convertMidTerms(int[] k) {
        int[] res = new int[3];
        if (k.length == 1) {
            res[0] = k[0];
        } else if (k.length != 3) {
            throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
        } else if (k[0] < k[1] && k[0] < k[2]) {
            res[0] = k[0];
            if (k[1] < k[2]) {
                res[1] = k[1];
                res[2] = k[2];
            } else {
                res[1] = k[2];
                res[2] = k[1];
            }
        } else if (k[1] < k[2]) {
            res[0] = k[1];
            if (k[0] < k[2]) {
                res[1] = k[0];
                res[2] = k[2];
            } else {
                res[1] = k[2];
                res[2] = k[0];
            }
        } else {
            res[0] = k[2];
            if (k[0] < k[1]) {
                res[1] = k[0];
                res[2] = k[1];
            } else {
                res[1] = k[1];
                res[2] = k[0];
            }
        }
        return res;
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key) throws InvalidKeyException {
        ECParameterSpec s;
        if (key instanceof ECPublicKey) {
            ECPublicKey k = (ECPublicKey) key;
            s = k.getParameters();
            if (s != null) {
                return new ECPublicKeyParameters(k.getQ(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
            }
            s = ProviderUtil.getEcImplicitlyCa();
            return new ECPublicKeyParameters(((JCEECPublicKey) k).engineGetQ(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        } else if (key instanceof java.security.interfaces.ECPublicKey) {
            java.security.interfaces.ECPublicKey pubKey = (java.security.interfaces.ECPublicKey) key;
            s = EC5Util.convertSpec(pubKey.getParams(), false);
            return new ECPublicKeyParameters(EC5Util.convertPoint(pubKey.getParams(), pubKey.getW(), false), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        } else {
            throw new InvalidKeyException("cannot identify EC public key.");
        }
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key) throws InvalidKeyException {
        if (key instanceof ECPrivateKey) {
            ECPrivateKey k = (ECPrivateKey) key;
            ECParameterSpec s = k.getParameters();
            if (s == null) {
                s = ProviderUtil.getEcImplicitlyCa();
            }
            return new ECPrivateKeyParameters(k.getD(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        }
        throw new InvalidKeyException("can't identify EC private key.");
    }

    public static DERObjectIdentifier getNamedCurveOid(String name) {
        DERObjectIdentifier oid = X962NamedCurves.getOID(name);
        if (oid != null) {
            return oid;
        }
        oid = SECNamedCurves.getOID(name);
        if (oid == null) {
            oid = NISTNamedCurves.getOID(name);
        }
        if (oid == null) {
            oid = TeleTrusTNamedCurves.getOID(name);
        }
        if (oid == null) {
            return ECGOST3410NamedCurves.getOID(name);
        }
        return oid;
    }

    public static X9ECParameters getNamedCurveByOid(DERObjectIdentifier oid) {
        X9ECParameters params = X962NamedCurves.getByOID(oid);
        if (params != null) {
            return params;
        }
        params = SECNamedCurves.getByOID(oid);
        if (params == null) {
            params = NISTNamedCurves.getByOID(oid);
        }
        if (params == null) {
            return TeleTrusTNamedCurves.getByOID(oid);
        }
        return params;
    }

    public static String getCurveName(DERObjectIdentifier oid) {
        String name = X962NamedCurves.getName(oid);
        if (name != null) {
            return name;
        }
        name = SECNamedCurves.getName(oid);
        if (name == null) {
            name = NISTNamedCurves.getName(oid);
        }
        if (name == null) {
            name = TeleTrusTNamedCurves.getName(oid);
        }
        if (name == null) {
            return ECGOST3410NamedCurves.getName(oid);
        }
        return name;
    }
}
