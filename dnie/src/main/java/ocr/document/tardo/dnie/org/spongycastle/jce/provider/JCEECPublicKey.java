package org.spongycastle.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.spongycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.X962Parameters;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9ECPoint;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.ECGOST3410NamedCurveTable;
import org.spongycastle.jce.interfaces.ECPointEncoder;
import org.spongycastle.jce.provider.asymmetric.ec.EC5Util;
import org.spongycastle.jce.provider.asymmetric.ec.ECUtil;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.F2m;
import org.spongycastle.math.ec.ECPoint.Fp;

public class JCEECPublicKey implements ECPublicKey, org.spongycastle.jce.interfaces.ECPublicKey, ECPointEncoder {
    private String algorithm = "EC";
    private ECParameterSpec ecSpec;
    private GOST3410PublicKeyAlgParameters gostParams;
    /* renamed from: q */
    private ECPoint f589q;
    private boolean withCompression;

    public JCEECPublicKey(String algorithm, JCEECPublicKey key) {
        this.algorithm = algorithm;
        this.f589q = key.f589q;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.gostParams = key.gostParams;
    }

    public JCEECPublicKey(String algorithm, ECPublicKeySpec spec) {
        this.algorithm = algorithm;
        this.ecSpec = spec.getParams();
        this.f589q = EC5Util.convertPoint(this.ecSpec, spec.getW(), false);
    }

    public JCEECPublicKey(String algorithm, org.spongycastle.jce.spec.ECPublicKeySpec spec) {
        this.algorithm = algorithm;
        this.f589q = spec.getQ();
        if (spec.getParams() != null) {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getParams().getCurve(), spec.getParams().getSeed()), spec.getParams());
            return;
        }
        if (this.f589q.getCurve() == null) {
            this.f589q = ProviderUtil.getEcImplicitlyCa().getCurve().createPoint(this.f589q.getX().toBigInteger(), this.f589q.getY().toBigInteger(), false);
        }
        this.ecSpec = null;
    }

    public JCEECPublicKey(String algorithm, ECPublicKeyParameters params, ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm;
        this.f589q = params.getQ();
        if (spec == null) {
            this.ecSpec = createSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), dp);
        } else {
            this.ecSpec = spec;
        }
    }

    public JCEECPublicKey(String algorithm, ECPublicKeyParameters params, org.spongycastle.jce.spec.ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();
        this.algorithm = algorithm;
        this.f589q = params.getQ();
        if (spec == null) {
            this.ecSpec = createSpec(EC5Util.convertCurve(dp.getCurve(), dp.getSeed()), dp);
        } else {
            this.ecSpec = EC5Util.convertSpec(EC5Util.convertCurve(spec.getCurve(), spec.getSeed()), spec);
        }
    }

    public JCEECPublicKey(String algorithm, ECPublicKeyParameters params) {
        this.algorithm = algorithm;
        this.f589q = params.getQ();
        this.ecSpec = null;
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp) {
        return new ECParameterSpec(ellipticCurve, new java.security.spec.ECPoint(dp.getG().getX().toBigInteger(), dp.getG().getY().toBigInteger()), dp.getN(), dp.getH().intValue());
    }

    public JCEECPublicKey(ECPublicKey key) {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.f589q = EC5Util.convertPoint(this.ecSpec, key.getW(), false);
    }

    JCEECPublicKey(SubjectPublicKeyInfo info) {
        populateFromPubKeyInfo(info);
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info) {
        if (info.getAlgorithmId().getObjectId().equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
            DERBitString bits = info.getPublicKeyData();
            this.algorithm = "ECGOST3410";
            try {
                int i;
                byte[] keyEnc = ((ASN1OctetString) ASN1Object.fromByteArray(bits.getBytes())).getOctets();
                byte[] x = new byte[32];
                byte[] y = new byte[32];
                for (i = 0; i != x.length; i++) {
                    x[i] = keyEnc[31 - i];
                }
                for (i = 0; i != y.length; i++) {
                    y[i] = keyEnc[63 - i];
                }
                this.gostParams = new GOST3410PublicKeyAlgParameters((ASN1Sequence) info.getAlgorithmId().getParameters());
                ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()));
                ECCurve curve = spec.getCurve();
                EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());
                this.f589q = curve.createPoint(new BigInteger(1, x), new BigInteger(1, y), false);
                this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()), ellipticCurve, new java.security.spec.ECPoint(spec.getG().getX().toBigInteger(), spec.getG().getY().toBigInteger()), spec.getN(), spec.getH());
                return;
            } catch (IOException e) {
                throw new IllegalArgumentException("error recovering public key");
            }
        }
        X962Parameters x962Parameters = new X962Parameters((DERObject) info.getAlgorithmId().getParameters());
        X9ECParameters ecP;
        if (x962Parameters.isNamedCurve()) {
            DERObjectIdentifier oid = (DERObjectIdentifier) x962Parameters.getParameters();
            ecP = ECUtil.getNamedCurveByOid(oid);
            curve = ecP.getCurve();
            this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), EC5Util.convertCurve(curve, ecP.getSeed()), new java.security.spec.ECPoint(ecP.getG().getX().toBigInteger(), ecP.getG().getY().toBigInteger()), ecP.getN(), ecP.getH());
        } else if (x962Parameters.isImplicitlyCA()) {
            this.ecSpec = null;
            curve = ProviderUtil.getEcImplicitlyCa().getCurve();
        } else {
            ecP = new X9ECParameters((ASN1Sequence) x962Parameters.getParameters());
            curve = ecP.getCurve();
            this.ecSpec = new ECParameterSpec(EC5Util.convertCurve(curve, ecP.getSeed()), new java.security.spec.ECPoint(ecP.getG().getX().toBigInteger(), ecP.getG().getY().toBigInteger()), ecP.getN(), ecP.getH().intValue());
        }
        byte[] data = info.getPublicKeyData().getBytes();
        ASN1OctetString key = new DEROctetString(data);
        if (data[0] == (byte) 4 && data[1] == data.length - 2 && ((data[2] == (byte) 2 || data[2] == (byte) 3) && new X9IntegerConverter().getByteLength(curve) >= data.length - 3)) {
            try {
                key = (ASN1OctetString) ASN1Object.fromByteArray(data);
            } catch (IOException e2) {
                throw new IllegalArgumentException("error recovering public key");
            }
        }
        this.f589q = new X9ECPoint(curve, key).getPoint();
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        SubjectPublicKeyInfo info;
        ASN1Encodable params;
        ECCurve curve;
        if (this.algorithm.equals("ECGOST3410")) {
            if (this.gostParams != null) {
                params = this.gostParams;
            } else if (this.ecSpec instanceof ECNamedCurveSpec) {
                params = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec) this.ecSpec).getName()), CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
            } else {
                curve = EC5Util.convertCurve(this.ecSpec.getCurve());
                params = new X962Parameters(new X9ECParameters(curve, EC5Util.convertPoint(curve, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
            }
            BigInteger bX = this.f589q.getX().toBigInteger();
            BigInteger bY = this.f589q.getY().toBigInteger();
            byte[] encKey = new byte[64];
            extractBytes(encKey, 0, bX);
            extractBytes(encKey, 32, bY);
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.getDERObject()), new DEROctetString(encKey));
        } else {
            if (this.ecSpec instanceof ECNamedCurveSpec) {
                DERObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) this.ecSpec).getName());
                if (curveOid == null) {
                    curveOid = new DERObjectIdentifier(((ECNamedCurveSpec) this.ecSpec).getName());
                }
                params = new X962Parameters(curveOid);
            } else if (this.ecSpec == null) {
                params = new X962Parameters(DERNull.INSTANCE);
            } else {
                curve = EC5Util.convertCurve(this.ecSpec.getCurve());
                params = new X962Parameters(new X9ECParameters(curve, EC5Util.convertPoint(curve, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long) this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed()));
            }
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), ((ASN1OctetString) new X9ECPoint(engineGetQ().getCurve().createPoint(getQ().getX().toBigInteger(), getQ().getY().toBigInteger(), this.withCompression)).getDERObject()).getOctets());
        }
        return info.getDEREncoded();
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI) {
        byte[] val = bI.toByteArray();
        if (val.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }
        for (int i = 0; i != 32; i++) {
            encKey[offSet + i] = val[(val.length - 1) - i];
        }
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

    public java.security.spec.ECPoint getW() {
        return new java.security.spec.ECPoint(this.f589q.getX().toBigInteger(), this.f589q.getY().toBigInteger());
    }

    public ECPoint getQ() {
        if (this.ecSpec != null) {
            return this.f589q;
        }
        if (this.f589q instanceof Fp) {
            return new Fp(null, this.f589q.getX(), this.f589q.getY());
        }
        return new F2m(null, this.f589q.getX(), this.f589q.getY());
    }

    public ECPoint engineGetQ() {
        return this.f589q;
    }

    org.spongycastle.jce.spec.ECParameterSpec engineGetSpec() {
        if (this.ecSpec != null) {
            return EC5Util.convertSpec(this.ecSpec, this.withCompression);
        }
        return ProviderUtil.getEcImplicitlyCa();
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("EC Public Key").append(nl);
        buf.append("            X: ").append(this.f589q.getX().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(this.f589q.getY().toBigInteger().toString(16)).append(nl);
        return buf.toString();
    }

    public void setPointFormat(String style) {
        this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(style);
    }

    public boolean equals(Object o) {
        if (!(o instanceof JCEECPublicKey)) {
            return false;
        }
        JCEECPublicKey other = (JCEECPublicKey) o;
        if (engineGetQ().equals(other.engineGetQ()) && engineGetSpec().equals(other.engineGetSpec())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return engineGetQ().hashCode() ^ engineGetSpec().hashCode();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray((byte[]) in.readObject())));
        this.algorithm = (String) in.readObject();
        this.withCompression = in.readBoolean();
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getEncoded());
        out.writeObject(this.algorithm);
        out.writeBoolean(this.withCompression);
    }
}
