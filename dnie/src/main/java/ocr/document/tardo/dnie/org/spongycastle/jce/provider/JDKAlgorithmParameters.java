package org.spongycastle.jce.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.RC2ParameterSpec;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.spongycastle.asn1.oiw.ElGamalParameter;
import org.spongycastle.asn1.pkcs.DHParameter;
import org.spongycastle.asn1.pkcs.PBKDF2Params;
import org.spongycastle.asn1.pkcs.PKCS12PBEParams;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.pkcs.RC2CBCParameter;
import org.spongycastle.asn1.pkcs.RSAESOAEPparams;
import org.spongycastle.asn1.pkcs.RSASSAPSSparams;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DSAParameter;
import org.spongycastle.jce.spec.ElGamalParameterSpec;
import org.spongycastle.jce.spec.GOST3410ParameterSpec;
import org.spongycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;
import org.spongycastle.jce.spec.IESParameterSpec;
import org.spongycastle.util.Arrays;

public abstract class JDKAlgorithmParameters extends AlgorithmParametersSpi {

    public static class DH extends JDKAlgorithmParameters {
        DHParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                return new DHParameter(this.currentSpec.getP(), this.currentSpec.getG(), this.currentSpec.getL()).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding DHParameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format)) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == DHParameterSpec.class) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to DH parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof DHParameterSpec) {
                this.currentSpec = (DHParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("DHParameterSpec required to initialise a Diffie-Hellman algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                DHParameter dhP = new DHParameter((ASN1Sequence) ASN1Object.fromByteArray(params));
                if (dhP.getL() != null) {
                    this.currentSpec = new DHParameterSpec(dhP.getP(), dhP.getG(), dhP.getL().intValue());
                } else {
                    this.currentSpec = new DHParameterSpec(dhP.getP(), dhP.getG());
                }
            } catch (ClassCastException e) {
                throw new IOException("Not a valid DH Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid DH Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format)) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "Diffie-Hellman Parameters";
        }
    }

    public static class DSA extends JDKAlgorithmParameters {
        DSAParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                return new DSAParameter(this.currentSpec.getP(), this.currentSpec.getQ(), this.currentSpec.getG()).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding DSAParameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format)) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == DSAParameterSpec.class) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to DSA parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof DSAParameterSpec) {
                this.currentSpec = (DSAParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("DSAParameterSpec required to initialise a DSA algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                DSAParameter dsaP = new DSAParameter((ASN1Sequence) ASN1Object.fromByteArray(params));
                this.currentSpec = new DSAParameterSpec(dsaP.getP(), dsaP.getQ(), dsaP.getG());
            } catch (ClassCastException e) {
                throw new IOException("Not a valid DSA Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid DSA Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "DSA Parameters";
        }
    }

    public static class ElGamal extends JDKAlgorithmParameters {
        ElGamalParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                return new ElGamalParameter(this.currentSpec.getP(), this.currentSpec.getG()).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding ElGamalParameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == ElGamalParameterSpec.class) {
                return this.currentSpec;
            }
            if (paramSpec == DHParameterSpec.class) {
                return new DHParameterSpec(this.currentSpec.getP(), this.currentSpec.getG());
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (!(paramSpec instanceof ElGamalParameterSpec) && !(paramSpec instanceof DHParameterSpec)) {
                throw new InvalidParameterSpecException("DHParameterSpec required to initialise a ElGamal algorithm parameters object");
            } else if (paramSpec instanceof ElGamalParameterSpec) {
                this.currentSpec = (ElGamalParameterSpec) paramSpec;
            } else {
                DHParameterSpec s = (DHParameterSpec) paramSpec;
                this.currentSpec = new ElGamalParameterSpec(s.getP(), s.getG());
            }
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                ElGamalParameter elP = new ElGamalParameter((ASN1Sequence) ASN1Object.fromByteArray(params));
                this.currentSpec = new ElGamalParameterSpec(elP.getP(), elP.getG());
            } catch (ClassCastException e) {
                throw new IOException("Not a valid ElGamal Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid ElGamal Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "ElGamal Parameters";
        }
    }

    public static class GOST3410 extends JDKAlgorithmParameters {
        GOST3410ParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                return new GOST3410PublicKeyAlgParameters(new DERObjectIdentifier(this.currentSpec.getPublicKeyParamSetOID()), new DERObjectIdentifier(this.currentSpec.getDigestParamSetOID()), new DERObjectIdentifier(this.currentSpec.getEncryptionParamSetOID())).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding GOST3410Parameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == GOST3410PublicKeyParameterSetSpec.class) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to GOST3410 parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof GOST3410ParameterSpec) {
                this.currentSpec = (GOST3410ParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("GOST3410ParameterSpec required to initialise a GOST3410 algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                this.currentSpec = GOST3410ParameterSpec.fromPublicKeyAlg(new GOST3410PublicKeyAlgParameters((ASN1Sequence) ASN1Object.fromByteArray(params)));
            } catch (ClassCastException e) {
                throw new IOException("Not a valid GOST3410 Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid GOST3410 Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "GOST3410 Parameters";
        }
    }

    public static class IES extends JDKAlgorithmParameters {
        IESParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(new DEROctetString(this.currentSpec.getDerivationV()));
                v.add(new DEROctetString(this.currentSpec.getEncodingV()));
                v.add(new DERInteger(this.currentSpec.getMacKeySize()));
                return new DERSequence(v).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding IESParameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == IESParameterSpec.class) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof IESParameterSpec) {
                this.currentSpec = (IESParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                ASN1Sequence s = (ASN1Sequence) ASN1Object.fromByteArray(params);
                this.currentSpec = new IESParameterSpec(((ASN1OctetString) s.getObjectAt(0)).getOctets(), ((ASN1OctetString) s.getObjectAt(0)).getOctets(), ((DERInteger) s.getObjectAt(0)).getValue().intValue());
            } catch (ClassCastException e) {
                throw new IOException("Not a valid IES Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid IES Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "IES Parameters";
        }
    }

    public static class IVAlgorithmParameters extends JDKAlgorithmParameters {
        private byte[] iv;

        protected byte[] engineGetEncoded() throws IOException {
            return engineGetEncoded("ASN.1");
        }

        protected byte[] engineGetEncoded(String format) throws IOException {
            if (isASN1FormatString(format)) {
                return new DEROctetString(engineGetEncoded("RAW")).getEncoded();
            }
            if (format.equals("RAW")) {
                return Arrays.clone(this.iv);
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == IvParameterSpec.class) {
                return new IvParameterSpec(this.iv);
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) paramSpec).getIV();
                return;
            }
            throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            if (params.length % 8 != 0 && params[0] == (byte) 4 && params[1] == params.length - 2) {
                params = ((ASN1OctetString) ASN1Object.fromByteArray(params)).getOctets();
            }
            this.iv = Arrays.clone(params);
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format)) {
                try {
                    engineInit(((ASN1OctetString) ASN1Object.fromByteArray(params)).getOctets());
                } catch (Exception e) {
                    throw new IOException("Exception decoding: " + e);
                }
            } else if (format.equals("RAW")) {
                engineInit(params);
            } else {
                throw new IOException("Unknown parameters format in IV parameters object");
            }
        }

        protected String engineToString() {
            return "IV Parameters";
        }
    }

    public static class OAEP extends JDKAlgorithmParameters {
        OAEPParameterSpec currentSpec;

        protected byte[] engineGetEncoded() {
            try {
                return new RSAESOAEPparams(new AlgorithmIdentifier(JCEDigestUtil.getOID(this.currentSpec.getDigestAlgorithm()), new DERNull()), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(JCEDigestUtil.getOID(((MGF1ParameterSpec) this.currentSpec.getMGFParameters()).getDigestAlgorithm()), new DERNull())), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(((PSpecified) this.currentSpec.getPSource()).getValue()))).getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Error encoding OAEPParameters");
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == OAEPParameterSpec.class && this.currentSpec != null) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to OAEP parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof OAEPParameterSpec) {
                this.currentSpec = (OAEPParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("OAEPParameterSpec required to initialise an OAEP algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                RSAESOAEPparams oaepP = new RSAESOAEPparams((ASN1Sequence) ASN1Object.fromByteArray(params));
                this.currentSpec = new OAEPParameterSpec(oaepP.getHashAlgorithm().getObjectId().getId(), oaepP.getMaskGenAlgorithm().getObjectId().getId(), new MGF1ParameterSpec(AlgorithmIdentifier.getInstance(oaepP.getMaskGenAlgorithm().getParameters()).getObjectId().getId()), new PSpecified(ASN1OctetString.getInstance(oaepP.getPSourceAlgorithm().getParameters()).getOctets()));
            } catch (ClassCastException e) {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (format.equalsIgnoreCase("X.509") || format.equalsIgnoreCase("ASN.1")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "OAEP Parameters";
        }
    }

    public static class PBKDF2 extends JDKAlgorithmParameters {
        PBKDF2Params params;

        protected byte[] engineGetEncoded() {
            try {
                return this.params.getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Oooops! " + e.toString());
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format)) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == PBEParameterSpec.class) {
                return new PBEParameterSpec(this.params.getSalt(), this.params.getIterationCount().intValue());
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof PBEParameterSpec) {
                PBEParameterSpec pbeSpec = (PBEParameterSpec) paramSpec;
                this.params = new PBKDF2Params(pbeSpec.getSalt(), pbeSpec.getIterationCount());
                return;
            }
            throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            this.params = PBKDF2Params.getInstance(ASN1Object.fromByteArray(params));
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format)) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameters format in PWRIKEK parameters object");
        }

        protected String engineToString() {
            return "PBKDF2 Parameters";
        }
    }

    public static class PKCS12PBE extends JDKAlgorithmParameters {
        PKCS12PBEParams params;

        protected byte[] engineGetEncoded() {
            try {
                return this.params.getEncoded("DER");
            } catch (IOException e) {
                throw new RuntimeException("Oooops! " + e.toString());
            }
        }

        protected byte[] engineGetEncoded(String format) {
            if (isASN1FormatString(format)) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == PBEParameterSpec.class) {
                return new PBEParameterSpec(this.params.getIV(), this.params.getIterations().intValue());
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof PBEParameterSpec) {
                PBEParameterSpec pbeSpec = (PBEParameterSpec) paramSpec;
                this.params = new PKCS12PBEParams(pbeSpec.getSalt(), pbeSpec.getIterationCount());
                return;
            }
            throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            this.params = PKCS12PBEParams.getInstance(ASN1Object.fromByteArray(params));
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format)) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameters format in PKCS12 PBE parameters object");
        }

        protected String engineToString() {
            return "PKCS12 PBE Parameters";
        }
    }

    public static class PSS extends JDKAlgorithmParameters {
        PSSParameterSpec currentSpec;

        protected byte[] engineGetEncoded() throws IOException {
            PSSParameterSpec pssSpec = this.currentSpec;
            return new RSASSAPSSparams(new AlgorithmIdentifier(JCEDigestUtil.getOID(pssSpec.getDigestAlgorithm()), new DERNull()), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(JCEDigestUtil.getOID(((MGF1ParameterSpec) pssSpec.getMGFParameters()).getDigestAlgorithm()), new DERNull())), new DERInteger(pssSpec.getSaltLength()), new DERInteger(pssSpec.getTrailerField())).getEncoded("DER");
        }

        protected byte[] engineGetEncoded(String format) throws IOException {
            if (format.equalsIgnoreCase("X.509") || format.equalsIgnoreCase("ASN.1")) {
                return engineGetEncoded();
            }
            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec == PSSParameterSpec.class && this.currentSpec != null) {
                return this.currentSpec;
            }
            throw new InvalidParameterSpecException("unknown parameter spec passed to PSS parameters object.");
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof PSSParameterSpec) {
                this.currentSpec = (PSSParameterSpec) paramSpec;
                return;
            }
            throw new InvalidParameterSpecException("PSSParameterSpec required to initialise an PSS algorithm parameters object");
        }

        protected void engineInit(byte[] params) throws IOException {
            try {
                RSASSAPSSparams pssP = new RSASSAPSSparams((ASN1Sequence) ASN1Object.fromByteArray(params));
                this.currentSpec = new PSSParameterSpec(pssP.getHashAlgorithm().getObjectId().getId(), pssP.getMaskGenAlgorithm().getObjectId().getId(), new MGF1ParameterSpec(AlgorithmIdentifier.getInstance(pssP.getMaskGenAlgorithm().getParameters()).getObjectId().getId()), pssP.getSaltLength().getValue().intValue(), pssP.getTrailerField().getValue().intValue());
            } catch (ClassCastException e) {
                throw new IOException("Not a valid PSS Parameter encoding.");
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new IOException("Not a valid PSS Parameter encoding.");
            }
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509")) {
                engineInit(params);
                return;
            }
            throw new IOException("Unknown parameter format " + format);
        }

        protected String engineToString() {
            return "PSS Parameters";
        }
    }

    public static class RC2AlgorithmParameters extends JDKAlgorithmParameters {
        private static final short[] ekb = new short[]{(short) 93, (short) 190, (short) 155, (short) 139, (short) 17, (short) 153, (short) 110, (short) 77, (short) 89, (short) 243, (short) 133, (short) 166, (short) 63, (short) 183, (short) 131, (short) 197, (short) 228, (short) 115, (short) 107, (short) 58, (short) 104, (short) 90, (short) 192, (short) 71, (short) 160, (short) 100, (short) 52, (short) 12, (short) 241, (short) 208, (short) 82, (short) 165, (short) 185, (short) 30, (short) 150, (short) 67, (short) 65, (short) 216, (short) 212, (short) 44, (short) 219, (short) 248, (short) 7, (short) 119, (short) 42, (short) 202, (short) 235, (short) 239, (short) 16, (short) 28, (short) 22, (short) 13, (short) 56, (short) 114, (short) 47, (short) 137, (short) 193, (short) 249, (short) 128, (short) 196, (short) 109, (short) 174, (short) 48, (short) 61, (short) 206, (short) 32, (short) 99, (short) 254, (short) 230, (short) 26, (short) 199, (short) 184, (short) 80, (short) 232, (short) 36, (short) 23, (short) 252, (short) 37, (short) 111, (short) 187, (short) 106, (short) 163, (short) 68, (short) 83, (short) 217, (short) 162, (short) 1, (short) 171, (short) 188, (short) 182, (short) 31, (short) 152, (short) 238, (short) 154, (short) 167, (short) 45, (short) 79, (short) 158, (short) 142, (short) 172, (short) 224, (short) 198, (short) 73, (short) 70, (short) 41, (short) 244, (short) 148, (short) 138, (short) 175, (short) 225, (short) 91, (short) 195, (short) 179, (short) 123, (short) 87, (short) 209, (short) 124, (short) 156, (short) 237, (short) 135, (short) 64, (short) 140, (short) 226, (short) 203, (short) 147, (short) 20, (short) 201, (short) 97, (short) 46, (short) 229, (short) 204, (short) 246, (short) 94, (short) 168, (short) 92, (short) 214, (short) 117, (short) 141, (short) 98, (short) 149, (short) 88, (short) 105, (short) 118, (short) 161, (short) 74, (short) 181, (short) 85, (short) 9, (short) 120, (short) 51, (short) 130, (short) 215, (short) 221, (short) 121, (short) 245, (short) 27, (short) 11, (short) 222, (short) 38, (short) 33, (short) 40, (short) 116, (short) 4, (short) 151, (short) 86, (short) 223, (short) 60, (short) 240, (short) 55, (short) 57, (short) 220, (short) 255, (short) 6, (short) 164, (short) 234, (short) 66, (short) 8, (short) 218, (short) 180, (short) 113, (short) 176, (short) 207, (short) 18, (short) 122, (short) 78, (short) 250, (short) 108, (short) 29, (short) 132, (short) 0, (short) 200, (short) 127, (short) 145, (short) 69, (short) 170, (short) 43, (short) 194, (short) 177, (short) 143, (short) 213, (short) 186, (short) 242, (short) 173, (short) 25, (short) 178, (short) 103, (short) 54, (short) 247, (short) 15, (short) 10, (short) 146, (short) 125, (short) 227, (short) 157, (short) 233, (short) 144, (short) 62, (short) 35, (short) 39, (short) 102, (short) 19, (short) 236, (short) 129, (short) 21, (short) 189, (short) 34, (short) 191, (short) 159, (short) 126, (short) 169, (short) 81, (short) 75, (short) 76, (short) 251, (short) 2, (short) 211, (short) 112, (short) 134, (short) 49, (short) 231, (short) 59, (short) 5, (short) 3, (short) 84, (short) 96, (short) 72, (short) 101, (short) 24, (short) 210, (short) 205, (short) 95, (short) 50, (short) 136, (short) 14, (short) 53, (short) 253};
        private static final short[] table = new short[]{(short) 189, (short) 86, (short) 234, (short) 242, (short) 162, (short) 241, (short) 172, (short) 42, (short) 176, (short) 147, (short) 209, (short) 156, (short) 27, (short) 51, (short) 253, (short) 208, (short) 48, (short) 4, (short) 182, (short) 220, (short) 125, (short) 223, (short) 50, (short) 75, (short) 247, (short) 203, (short) 69, (short) 155, (short) 49, (short) 187, (short) 33, (short) 90, (short) 65, (short) 159, (short) 225, (short) 217, (short) 74, (short) 77, (short) 158, (short) 218, (short) 160, (short) 104, (short) 44, (short) 195, (short) 39, (short) 95, (short) 128, (short) 54, (short) 62, (short) 238, (short) 251, (short) 149, (short) 26, (short) 254, (short) 206, (short) 168, (short) 52, (short) 169, (short) 19, (short) 240, (short) 166, (short) 63, (short) 216, (short) 12, (short) 120, (short) 36, (short) 175, (short) 35, (short) 82, (short) 193, (short) 103, (short) 23, (short) 245, (short) 102, (short) 144, (short) 231, (short) 232, (short) 7, (short) 184, (short) 96, (short) 72, (short) 230, (short) 30, (short) 83, (short) 243, (short) 146, (short) 164, (short) 114, (short) 140, (short) 8, (short) 21, (short) 110, (short) 134, (short) 0, (short) 132, (short) 250, (short) 244, (short) 127, (short) 138, (short) 66, (short) 25, (short) 246, (short) 219, (short) 205, (short) 20, (short) 141, (short) 80, (short) 18, (short) 186, (short) 60, (short) 6, (short) 78, (short) 236, (short) 179, (short) 53, (short) 17, (short) 161, (short) 136, (short) 142, (short) 43, (short) 148, (short) 153, (short) 183, (short) 113, (short) 116, (short) 211, (short) 228, (short) 191, (short) 58, (short) 222, (short) 150, (short) 14, (short) 188, (short) 10, (short) 237, (short) 119, (short) 252, (short) 55, (short) 107, (short) 3, (short) 121, (short) 137, (short) 98, (short) 198, (short) 215, (short) 192, (short) 210, (short) 124, (short) 106, (short) 139, (short) 34, (short) 163, (short) 91, (short) 5, (short) 93, (short) 2, (short) 117, (short) 213, (short) 97, (short) 227, (short) 24, (short) 143, (short) 85, (short) 81, (short) 173, (short) 31, (short) 11, (short) 94, (short) 133, (short) 229, (short) 194, (short) 87, (short) 99, (short) 202, (short) 61, (short) 108, (short) 180, (short) 197, (short) 204, (short) 112, (short) 178, (short) 145, (short) 89, (short) 13, (short) 71, (short) 32, (short) 200, (short) 79, (short) 88, (short) 224, (short) 1, (short) 226, (short) 22, (short) 56, (short) 196, (short) 111, (short) 59, (short) 15, (short) 101, (short) 70, (short) 190, (short) 126, (short) 45, (short) 123, (short) 130, (short) 249, (short) 64, (short) 181, (short) 29, (short) 115, (short) 248, (short) 235, (short) 38, (short) 199, (short) 135, (short) 151, (short) 37, (short) 84, (short) 177, (short) 40, (short) 170, (short) 152, (short) 157, (short) 165, (short) 100, (short) 109, (short) 122, (short) 212, (short) 16, (short) 129, (short) 68, (short) 239, (short) 73, (short) 214, (short) 174, (short) 46, (short) 221, (short) 118, (short) 92, (short) 47, (short) 167, (short) 28, (short) 201, (short) 9, (short) 105, (short) 154, (short) 131, (short) 207, (short) 41, (short) 57, (short) 185, (short) 233, (short) 76, (short) 255, (short) 67, (short) 171};
        private byte[] iv;
        private int parameterVersion = 58;

        protected byte[] engineGetEncoded() {
            return Arrays.clone(this.iv);
        }

        protected byte[] engineGetEncoded(String format) throws IOException {
            if (isASN1FormatString(format)) {
                if (this.parameterVersion == -1) {
                    return new RC2CBCParameter(engineGetEncoded()).getEncoded();
                }
                return new RC2CBCParameter(this.parameterVersion, engineGetEncoded()).getEncoded();
            } else if (format.equals("RAW")) {
                return engineGetEncoded();
            } else {
                return null;
            }
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
            if (paramSpec != RC2ParameterSpec.class || this.parameterVersion == -1) {
                if (paramSpec == IvParameterSpec.class) {
                    return new IvParameterSpec(this.iv);
                }
                throw new InvalidParameterSpecException("unknown parameter spec passed to RC2 parameters object.");
            } else if (this.parameterVersion < 256) {
                return new RC2ParameterSpec(ekb[this.parameterVersion], this.iv);
            } else {
                return new RC2ParameterSpec(this.parameterVersion, this.iv);
            }
        }

        protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
            if (paramSpec instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) paramSpec).getIV();
            } else if (paramSpec instanceof RC2ParameterSpec) {
                int effKeyBits = ((RC2ParameterSpec) paramSpec).getEffectiveKeyBits();
                if (effKeyBits != -1) {
                    if (effKeyBits < 256) {
                        this.parameterVersion = table[effKeyBits];
                    } else {
                        this.parameterVersion = effKeyBits;
                    }
                }
                this.iv = ((RC2ParameterSpec) paramSpec).getIV();
            } else {
                throw new InvalidParameterSpecException("IvParameterSpec or RC2ParameterSpec required to initialise a RC2 parameters algorithm parameters object");
            }
        }

        protected void engineInit(byte[] params) throws IOException {
            this.iv = Arrays.clone(params);
        }

        protected void engineInit(byte[] params, String format) throws IOException {
            if (isASN1FormatString(format)) {
                RC2CBCParameter p = RC2CBCParameter.getInstance(ASN1Object.fromByteArray(params));
                if (p.getRC2ParameterVersion() != null) {
                    this.parameterVersion = p.getRC2ParameterVersion().intValue();
                }
                this.iv = p.getIV();
            } else if (format.equals("RAW")) {
                engineInit(params);
            } else {
                throw new IOException("Unknown parameters format in IV parameters object");
            }
        }

        protected String engineToString() {
            return "RC2 Parameters";
        }
    }

    protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class cls) throws InvalidParameterSpecException;

    protected boolean isASN1FormatString(String format) {
        return format == null || format.equals("ASN.1");
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null) {
            return localEngineGetParameterSpec(paramSpec);
        }
        throw new NullPointerException("argument to getParameterSpec must not be null");
    }
}
