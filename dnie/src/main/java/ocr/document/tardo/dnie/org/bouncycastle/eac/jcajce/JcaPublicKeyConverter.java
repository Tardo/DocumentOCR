package org.bouncycastle.eac.jcajce;

import java.math.BigInteger;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.asn1.eac.RSAPublicKey;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;

public class JcaPublicKeyConverter {
    private EACHelper helper = new DefaultEACHelper();

    private static ECCurve convertCurve(EllipticCurve ellipticCurve) {
        ECField field = ellipticCurve.getField();
        BigInteger a = ellipticCurve.getA();
        BigInteger b = ellipticCurve.getB();
        if (field instanceof ECFieldFp) {
            return new Fp(((ECFieldFp) field).getP(), a, b);
        }
        throw new IllegalStateException("not implemented yet!!!");
    }

    private static ECPoint convertPoint(ECCurve eCCurve, java.security.spec.ECPoint eCPoint, boolean z) {
        return eCCurve.createPoint(eCPoint.getAffineX(), eCPoint.getAffineY(), z);
    }

    private PublicKey getECPublicKeyPublicKey(ECDSAPublicKey eCDSAPublicKey) throws EACException, InvalidKeySpecException {
        ECParameterSpec params = getParams(eCDSAPublicKey);
        try {
            return this.helper.createKeyFactory("ECDSA").generatePublic(new ECPublicKeySpec(params.getCurve().decodePoint(eCDSAPublicKey.getPublicPointY()), params));
        } catch (Throwable e) {
            throw new EACException("cannot find provider: " + e.getMessage(), e);
        } catch (Throwable e2) {
            throw new EACException("cannot find algorithm ECDSA: " + e2.getMessage(), e2);
        }
    }

    private ECParameterSpec getParams(ECDSAPublicKey eCDSAPublicKey) {
        if (eCDSAPublicKey.hasParameters()) {
            ECCurve fp = new Fp(eCDSAPublicKey.getPrimeModulusP(), eCDSAPublicKey.getFirstCoefA(), eCDSAPublicKey.getSecondCoefB());
            return new ECParameterSpec(fp, fp.decodePoint(eCDSAPublicKey.getBasePointG()), eCDSAPublicKey.getOrderOfBasePointR(), eCDSAPublicKey.getCofactorF());
        }
        throw new IllegalArgumentException("Public key does not contains EC Params");
    }

    public PublicKey getKey(PublicKeyDataObject publicKeyDataObject) throws EACException, InvalidKeySpecException {
        if (publicKeyDataObject.getUsage().on(EACObjectIdentifiers.id_TA_ECDSA)) {
            return getECPublicKeyPublicKey((ECDSAPublicKey) publicKeyDataObject);
        }
        RSAPublicKey rSAPublicKey = (RSAPublicKey) publicKeyDataObject;
        try {
            return this.helper.createKeyFactory("RSA").generatePublic(new RSAPublicKeySpec(rSAPublicKey.getModulus(), rSAPublicKey.getPublicExponent()));
        } catch (Throwable e) {
            throw new EACException("cannot find provider: " + e.getMessage(), e);
        } catch (Throwable e2) {
            throw new EACException("cannot find algorithm ECDSA: " + e2.getMessage(), e2);
        }
    }

    public PublicKeyDataObject getPublicKeyDataObject(ASN1ObjectIdentifier aSN1ObjectIdentifier, PublicKey publicKey) {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rSAPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
            return new RSAPublicKey(aSN1ObjectIdentifier, rSAPublicKey.getModulus(), rSAPublicKey.getPublicExponent());
        }
        ECPublicKey eCPublicKey = (ECPublicKey) publicKey;
        java.security.spec.ECParameterSpec params = eCPublicKey.getParams();
        return new ECDSAPublicKey(aSN1ObjectIdentifier, ((ECFieldFp) params.getCurve().getField()).getP(), params.getCurve().getA(), params.getCurve().getB(), convertPoint(convertCurve(params.getCurve()), params.getGenerator(), false).getEncoded(), params.getOrder(), convertPoint(convertCurve(params.getCurve()), eCPublicKey.getW(), false).getEncoded(), params.getCofactor());
    }

    public JcaPublicKeyConverter setProvider(String str) {
        this.helper = new NamedEACHelper(str);
        return this;
    }

    public JcaPublicKeyConverter setProvider(Provider provider) {
        this.helper = new ProviderEACHelper(provider);
        return this;
    }
}
