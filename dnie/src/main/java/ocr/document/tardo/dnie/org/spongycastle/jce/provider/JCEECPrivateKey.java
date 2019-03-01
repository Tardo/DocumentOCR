package org.spongycastle.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.sec.ECPrivateKeyStructure;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.X962Parameters;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.jce.interfaces.ECPointEncoder;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.jce.provider.asymmetric.ec.EC5Util;
import org.spongycastle.jce.provider.asymmetric.ec.ECUtil;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.math.ec.ECCurve;

public class JCEECPrivateKey implements ECPrivateKey, org.spongycastle.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder {
    private String algorithm = "EC";
    private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
    /* renamed from: d */
    private BigInteger f588d;
    private ECParameterSpec ecSpec;
    private DERBitString publicKey;
    private boolean withCompression;

    protected JCEECPrivateKey() {
    }

    public JCEECPrivateKey(ECPrivateKey key) {
        this.f588d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    public JCEECPrivateKey(String algorithm, ECPrivateKeySpec spec) {
        this.algorithm = algorithm;
        this.f588d = spec.getD();
        if (spec.getParams() != null) {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getParams().getCurve(), spec.getParams().getSeed()), spec.getParams());
        } else {
            this.ecSpec = null;
        }
    }

    public JCEECPrivateKey(String algorithm, java.security.spec.ECPrivateKeySpec spec) {
        this.algorithm = algorithm;
        this.f588d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    public JCEECPrivateKey(String algorithm, JCEECPrivateKey key) {
        this.algorithm = algorithm;
        this.f588d = key.f588d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
    }

    public JCEECPrivateKey(String algorithm, ECPrivateKeyParameters params, JCEECPublicKey pubKey, ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm;
        this.f588d = params.getD();
        if (spec == null) {
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), new ECPoint(dp.getG().getX().toBigInteger(), dp.getG().getY().toBigInteger()), dp.getN(), dp.getH().intValue());
        } else {
            this.ecSpec = spec;
        }
        this.publicKey = getPublicKeyDetails(pubKey);
    }

    public JCEECPrivateKey(String algorithm, ECPrivateKeyParameters params, JCEECPublicKey pubKey, org.spongycastle.jce.spec.ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm;
        this.f588d = params.getD();
        if (spec == null) {
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), new ECPoint(dp.getG().getX().toBigInteger(), dp.getG().getY().toBigInteger()), dp.getN(), dp.getH().intValue());
        } else {
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(spec.getCurve(), spec.getSeed()), new ECPoint(spec.getG().getX().toBigInteger(), spec.getG().getY().toBigInteger()), spec.getN(), spec.getH().intValue());
        }
        this.publicKey = getPublicKeyDetails(pubKey);
    }

    public JCEECPrivateKey(String algorithm, ECPrivateKeyParameters params) {
        this.algorithm = algorithm;
        this.f588d = params.getD();
        this.ecSpec = null;
    }

    JCEECPrivateKey(PrivateKeyInfo info) {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info) {
        X962Parameters params = new X962Parameters((DERObject) info.getAlgorithmId().getParameters());
        X9ECParameters ecP;
        if (params.isNamedCurve()) {
            DERObjectIdentifier oid = (DERObjectIdentifier) params.getParameters();
            ecP = ECUtil.getNamedCurveByOid(oid);
            if (ecP == null) {
                ECDomainParameters gParam = ECGOST3410NamedCurves.getByOID(oid);
                this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(oid), EC5Util.convertCurve(gParam.getCurve(), gParam.getSeed()), new ECPoint(gParam.getG().getX().toBigInteger(), gParam.getG().getY().toBigInteger()), gParam.getN(), gParam.getH());
            } else {
                this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed()), new ECPoint(ecP.getG().getX().toBigInteger(), ecP.getG().getY().toBigInteger()), ecP.getN(), ecP.getH());
            }
        } else if (params.isImplicitlyCA()) {
            this.ecSpec = null;
        } else {
            ecP = new X9ECParameters((ASN1Sequence) params.getParameters());
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed()), new ECPoint(ecP.getG().getX().toBigInteger(), ecP.getG().getY().toBigInteger()), ecP.getN(), ecP.getH().intValue());
        }
        if (info.getPrivateKey() instanceof DERInteger) {
            this.f588d = ((DERInteger) info.getPrivateKey()).getValue();
            return;
        }
        ECPrivateKeyStructure ec = new ECPrivateKeyStructure((ASN1Sequence) info.getPrivateKey());
        this.f588d = ec.getKey();
        this.publicKey = ec.getPublicKey();
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        X962Parameters params;
        ECPrivateKeyStructure keyStructure;
        PrivateKeyInfo info;
        if (this.ecSpec instanceof ECNamedCurveSpec) {
            DERObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) this.ecSpec).getName());
            if (curveOid == null) {
                curveOid = new DERObjectIdentifier(((ECNamedCurveSpec) this.ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        } else if (this.ecSpec == null) {
            params = new X962Parameters(DERNull.INSTANCE);
        } else {
            ECCurve curve = EC5Util.convertCurve(this.ecSpec.getCurve());
            params = new X962Parameters(new X9ECParameters(curve, EC5Util.convertPoint(curve, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
        }
        if (this.publicKey != null) {
            keyStructure = new ECPrivateKeyStructure(getS(), this.publicKey, params);
        } else {
            keyStructure = new ECPrivateKeyStructure(getS(), params);
        }
        if (this.algorithm.equals("ECGOST3410")) {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.getDERObject()), keyStructure.getDERObject());
        } else {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), keyStructure.getDERObject());
        }
        return info.getDEREncoded();
    }

    public ECParameterSpec getParams() {
        return this.ecSpec;
    }

    public org.spongycastle.jce.spec.ECParameterSpec getParameters() {
        if (this.ecSpec == null) {
            return null;
        }
        return EC5Util.convertSpec(this.ecSpec, this.withCompression);
    }

    org.spongycastle.jce.spec.ECParameterSpec engineGetSpec() {
        if (this.ecSpec != null) {
            return EC5Util.convertSpec(this.ecSpec, this.withCompression);
        }
        return ProviderUtil.getEcImplicitlyCa();
    }

    public BigInteger getS() {
        return this.f588d;
    }

    public BigInteger getD() {
        return this.f588d;
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

    public void setPointFormat(String style) {
        this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(style);
    }

    public boolean equals(Object o) {
        if (!(o instanceof JCEECPrivateKey)) {
            return false;
        }
        JCEECPrivateKey other = (JCEECPrivateKey) o;
        if (getD().equals(other.getD()) && engineGetSpec().equals(other.engineGetSpec())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("EC Private Key").append(nl);
        buf.append("             S: ").append(this.f588d.toString(16)).append(nl);
        return buf.toString();
    }

    private DERBitString getPublicKeyDetails(JCEECPublicKey pub) {
        try {
            return SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(pub.getEncoded())).getPublicKeyData();
        } catch (IOException e) {
            return null;
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Object.fromByteArray((byte[]) in.readObject())));
        this.algorithm = (String) in.readObject();
        this.withCompression = in.readBoolean();
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
        this.attrCarrier.readObject(in);
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getEncoded());
        out.writeObject(this.algorithm);
        out.writeBoolean(this.withCompression);
        this.attrCarrier.writeObject(out);
    }
}
