package org.spongycastle.jce.provider;

import java.math.BigInteger;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.spongycastle.jce.interfaces.GOST3410Params;
import org.spongycastle.jce.interfaces.GOST3410PrivateKey;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.jce.spec.GOST3410ParameterSpec;
import org.spongycastle.jce.spec.GOST3410PrivateKeySpec;
import org.spongycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public class JDKGOST3410PrivateKey implements GOST3410PrivateKey, PKCS12BagAttributeCarrier {
    private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();
    GOST3410Params gost3410Spec;
    /* renamed from: x */
    BigInteger f592x;

    protected JDKGOST3410PrivateKey() {
    }

    JDKGOST3410PrivateKey(GOST3410PrivateKey key) {
        this.f592x = key.getX();
        this.gost3410Spec = key.getParameters();
    }

    JDKGOST3410PrivateKey(GOST3410PrivateKeySpec spec) {
        this.f592x = spec.getX();
        this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
    }

    JDKGOST3410PrivateKey(PrivateKeyInfo info) {
        GOST3410PublicKeyAlgParameters params = new GOST3410PublicKeyAlgParameters((ASN1Sequence) info.getAlgorithmId().getParameters());
        byte[] keyEnc = ((DEROctetString) info.getPrivateKey()).getOctets();
        byte[] keyBytes = new byte[keyEnc.length];
        for (int i = 0; i != keyEnc.length; i++) {
            keyBytes[i] = keyEnc[(keyEnc.length - 1) - i];
        }
        this.f592x = new BigInteger(1, keyBytes);
        this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(params);
    }

    JDKGOST3410PrivateKey(GOST3410PrivateKeyParameters params, GOST3410ParameterSpec spec) {
        this.f592x = params.getX();
        this.gost3410Spec = spec;
        if (spec == null) {
            throw new IllegalArgumentException("spec is null");
        }
    }

    public String getAlgorithm() {
        return "GOST3410";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        byte[] keyBytes;
        PrivateKeyInfo info;
        byte[] keyEnc = getX().toByteArray();
        if (keyEnc[0] == (byte) 0) {
            keyBytes = new byte[(keyEnc.length - 1)];
        } else {
            keyBytes = new byte[keyEnc.length];
        }
        for (int i = 0; i != keyBytes.length; i++) {
            keyBytes[i] = keyEnc[(keyEnc.length - 1) - i];
        }
        if (this.gost3410Spec instanceof GOST3410ParameterSpec) {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new DERObjectIdentifier(this.gost3410Spec.getPublicKeyParamSetOID()), new DERObjectIdentifier(this.gost3410Spec.getDigestParamSetOID())).getDERObject()), new DEROctetString(keyBytes));
        } else {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(keyBytes));
        }
        return info.getDEREncoded();
    }

    public GOST3410Params getParameters() {
        return this.gost3410Spec;
    }

    public BigInteger getX() {
        return this.f592x;
    }

    public void setBagAttribute(DERObjectIdentifier oid, DEREncodable attribute) {
        this.attrCarrier.setBagAttribute(oid, attribute);
    }

    public DEREncodable getBagAttribute(DERObjectIdentifier oid) {
        return this.attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys() {
        return this.attrCarrier.getBagAttributeKeys();
    }
}
