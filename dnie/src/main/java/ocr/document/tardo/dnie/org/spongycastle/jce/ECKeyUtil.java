package org.spongycastle.jce;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.X962Parameters;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
import org.spongycastle.jce.provider.ProviderUtil;
import org.spongycastle.jce.provider.asymmetric.ec.ECUtil;

public class ECKeyUtil {

    private static class UnexpectedException extends RuntimeException {
        private Throwable cause;

        UnexpectedException(Throwable cause) {
            super(cause.toString());
            this.cause = cause;
        }

        public Throwable getCause() {
            return this.cause;
        }
    }

    public static PublicKey publicToExplicitParameters(PublicKey key, String providerName) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException {
        Provider provider = Security.getProvider(providerName);
        if (provider != null) {
            return publicToExplicitParameters(key, provider);
        }
        throw new NoSuchProviderException("cannot find provider: " + providerName);
    }

    public static PublicKey publicToExplicitParameters(PublicKey key, Provider provider) throws IllegalArgumentException, NoSuchAlgorithmException {
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(key.getEncoded()));
            if (info.getAlgorithmId().getObjectId().equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
                throw new IllegalArgumentException("cannot convert GOST key to explicit parameters.");
            }
            X9ECParameters curveParams;
            X962Parameters params = new X962Parameters((DERObject) info.getAlgorithmId().getParameters());
            if (params.isNamedCurve()) {
                curveParams = ECUtil.getNamedCurveByOid((DERObjectIdentifier) params.getParameters());
                curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());
            } else if (!params.isImplicitlyCA()) {
                return key;
            } else {
                curveParams = new X9ECParameters(ProviderUtil.getEcImplicitlyCa().getCurve(), ProviderUtil.getEcImplicitlyCa().getG(), ProviderUtil.getEcImplicitlyCa().getN(), ProviderUtil.getEcImplicitlyCa().getH());
            }
            SubjectPublicKeyInfo info2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(curveParams).getDERObject()), info.getPublicKeyData().getBytes());
            info = info2;
            return KeyFactory.getInstance(key.getAlgorithm(), provider).generatePublic(new X509EncodedKeySpec(info2.getEncoded()));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (NoSuchAlgorithmException e2) {
            throw e2;
        } catch (Exception e3) {
            throw new UnexpectedException(e3);
        }
    }

    public static PrivateKey privateToExplicitParameters(PrivateKey key, String providerName) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException {
        Provider provider = Security.getProvider(providerName);
        if (provider != null) {
            return privateToExplicitParameters(key, provider);
        }
        throw new NoSuchProviderException("cannot find provider: " + providerName);
    }

    public static PrivateKey privateToExplicitParameters(PrivateKey key, Provider provider) throws IllegalArgumentException, NoSuchAlgorithmException {
        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Object.fromByteArray(key.getEncoded()));
            if (info.getAlgorithmId().getObjectId().equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
                throw new UnsupportedEncodingException("cannot convert GOST key to explicit parameters.");
            }
            X9ECParameters curveParams;
            X962Parameters params = new X962Parameters((DERObject) info.getAlgorithmId().getParameters());
            if (params.isNamedCurve()) {
                curveParams = ECUtil.getNamedCurveByOid((DERObjectIdentifier) params.getParameters());
                curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());
            } else if (!params.isImplicitlyCA()) {
                return key;
            } else {
                curveParams = new X9ECParameters(ProviderUtil.getEcImplicitlyCa().getCurve(), ProviderUtil.getEcImplicitlyCa().getG(), ProviderUtil.getEcImplicitlyCa().getN(), ProviderUtil.getEcImplicitlyCa().getH());
            }
            PrivateKeyInfo info2 = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(curveParams).getDERObject()), info.getPrivateKey());
            info = info2;
            return KeyFactory.getInstance(key.getAlgorithm(), provider).generatePrivate(new PKCS8EncodedKeySpec(info2.getEncoded()));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (NoSuchAlgorithmException e2) {
            throw e2;
        } catch (Exception e3) {
            throw new UnexpectedException(e3);
        }
    }
}
