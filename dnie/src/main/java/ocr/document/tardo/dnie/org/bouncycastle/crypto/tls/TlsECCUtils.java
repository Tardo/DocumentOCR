package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

public class TlsECCUtils {
    public static final Integer EXT_ec_point_formats = Integers.valueOf(11);
    public static final Integer EXT_elliptic_curves = Integers.valueOf(10);
    private static final String[] curveNames = new String[]{"sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1"};

    public static void addSupportedEllipticCurvesExtension(Hashtable hashtable, int[] iArr) throws IOException {
        hashtable.put(EXT_elliptic_curves, createSupportedEllipticCurvesExtension(iArr));
    }

    public static void addSupportedPointFormatsExtension(Hashtable hashtable, short[] sArr) throws IOException {
        hashtable.put(EXT_ec_point_formats, createSupportedPointFormatsExtension(sArr));
    }

    public static boolean areOnSameCurve(ECDomainParameters eCDomainParameters, ECDomainParameters eCDomainParameters2) {
        return eCDomainParameters.getCurve().equals(eCDomainParameters2.getCurve()) && eCDomainParameters.getG().equals(eCDomainParameters2.getG()) && eCDomainParameters.getN().equals(eCDomainParameters2.getN()) && eCDomainParameters.getH().equals(eCDomainParameters2.getH());
    }

    public static byte[] calculateECDHBasicAgreement(ECPublicKeyParameters eCPublicKeyParameters, ECPrivateKeyParameters eCPrivateKeyParameters) {
        ECDHBasicAgreement eCDHBasicAgreement = new ECDHBasicAgreement();
        eCDHBasicAgreement.init(eCPrivateKeyParameters);
        return BigIntegers.asUnsignedByteArray(eCDHBasicAgreement.getFieldSize(), eCDHBasicAgreement.calculateAgreement(eCPublicKeyParameters));
    }

    public static boolean containsECCCipherSuites(int[] iArr) {
        for (int isECCCipherSuite : iArr) {
            if (isECCCipherSuite(isECCCipherSuite)) {
                return true;
            }
        }
        return false;
    }

    public static byte[] createSupportedEllipticCurvesExtension(int[] iArr) throws IOException {
        if (iArr == null || iArr.length < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint16(iArr.length * 2, byteArrayOutputStream);
        TlsUtils.writeUint16Array(iArr, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] createSupportedPointFormatsExtension(short[] sArr) throws IOException {
        if (sArr == null) {
            sArr = new short[]{(short) 0};
        } else if (!TlsProtocol.arrayContains(sArr, (short) 0)) {
            Object obj = new short[(sArr.length + 1)];
            System.arraycopy(sArr, 0, obj, 0, sArr.length);
            obj[sArr.length] = null;
            Object obj2 = obj;
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8((short) sArr.length, byteArrayOutputStream);
        TlsUtils.writeUint8Array(sArr, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static BigInteger deserializeECFieldElement(int i, byte[] bArr) throws IOException {
        if (bArr.length == (i + 7) / 8) {
            return new BigInteger(1, bArr);
        }
        throw new TlsFatalAlert((short) 50);
    }

    public static ECPoint deserializeECPoint(short[] sArr, ECCurve eCCurve, byte[] bArr) throws IOException {
        return eCCurve.decodePoint(bArr);
    }

    public static ECPublicKeyParameters deserializeECPublicKey(short[] sArr, ECDomainParameters eCDomainParameters, byte[] bArr) throws IOException {
        try {
            return new ECPublicKeyParameters(deserializeECPoint(sArr, eCDomainParameters.getCurve(), bArr), eCDomainParameters);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 47);
        }
    }

    public static AsymmetricCipherKeyPair generateECKeyPair(SecureRandom secureRandom, ECDomainParameters eCDomainParameters) {
        ECKeyPairGenerator eCKeyPairGenerator = new ECKeyPairGenerator();
        eCKeyPairGenerator.init(new ECKeyGenerationParameters(eCDomainParameters, secureRandom));
        return eCKeyPairGenerator.generateKeyPair();
    }

    public static String getNameOfNamedCurve(int i) {
        return isSupportedNamedCurve(i) ? curveNames[i - 1] : null;
    }

    public static ECDomainParameters getParametersForNamedCurve(int i) {
        String nameOfNamedCurve = getNameOfNamedCurve(i);
        if (nameOfNamedCurve == null) {
            return null;
        }
        X9ECParameters byName = SECNamedCurves.getByName(nameOfNamedCurve);
        return byName != null ? new ECDomainParameters(byName.getCurve(), byName.getG(), byName.getN(), byName.getH(), byName.getSeed()) : null;
    }

    public static int[] getSupportedEllipticCurvesExtension(Hashtable hashtable) throws IOException {
        if (hashtable == null) {
            return null;
        }
        byte[] bArr = (byte[]) hashtable.get(EXT_elliptic_curves);
        return bArr == null ? null : readSupportedEllipticCurvesExtension(bArr);
    }

    public static short[] getSupportedPointFormatsExtension(Hashtable hashtable) throws IOException {
        if (hashtable == null) {
            return null;
        }
        byte[] bArr = (byte[]) hashtable.get(EXT_ec_point_formats);
        return bArr == null ? null : readSupportedPointFormatsExtension(bArr);
    }

    public static boolean hasAnySupportedNamedCurves() {
        return curveNames.length > 0;
    }

    public static boolean isCompressionPreferred(short[] sArr, short s) {
        if (sArr == null) {
            return false;
        }
        for (short s2 : sArr) {
            if (s2 == (short) 0) {
                return false;
            }
            if (s2 == s) {
                return true;
            }
        }
        return false;
    }

    public static boolean isECCCipherSuite(int i) {
        switch (i) {
            case 49153:
            case 49154:
            case 49155:
            case 49156:
            case 49157:
            case 49158:
            case 49159:
            case 49160:
            case 49161:
            case 49162:
            case 49163:
            case 49164:
            case 49165:
            case 49166:
            case 49167:
            case 49168:
            case 49169:
            case 49170:
            case 49171:
            case 49172:
            case 49173:
            case 49174:
            case 49175:
            case 49176:
            case 49177:
            case 49187:
            case 49188:
            case 49189:
            case 49190:
            case 49191:
            case 49192:
            case 49193:
            case 49194:
            case 49195:
            case 49196:
            case 49197:
            case 49198:
            case 49199:
            case 49200:
            case 49201:
            case 49202:
                return true;
            default:
                return false;
        }
    }

    public static boolean isSupportedNamedCurve(int i) {
        return i > 0 && i <= curveNames.length;
    }

    public static int readECExponent(int i, InputStream inputStream) throws IOException {
        BigInteger readECParameter = readECParameter(inputStream);
        if (readECParameter.bitLength() < 32) {
            int intValue = readECParameter.intValue();
            if (intValue > 0 && intValue < i) {
                return intValue;
            }
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static BigInteger readECFieldElement(int i, InputStream inputStream) throws IOException {
        return deserializeECFieldElement(i, TlsUtils.readOpaque8(inputStream));
    }

    public static BigInteger readECParameter(InputStream inputStream) throws IOException {
        return new BigInteger(1, TlsUtils.readOpaque8(inputStream));
    }

    public static ECDomainParameters readECParameters(int[] iArr, short[] sArr, InputStream inputStream) throws IOException {
        try {
            switch (TlsUtils.readUint8(inputStream)) {
                case (short) 1:
                    BigInteger readECParameter = readECParameter(inputStream);
                    ECCurve fp = new Fp(readECParameter, readECFieldElement(readECParameter.bitLength(), inputStream), readECFieldElement(readECParameter.bitLength(), inputStream));
                    return new ECDomainParameters(fp, deserializeECPoint(sArr, fp, TlsUtils.readOpaque8(inputStream)), readECParameter(inputStream), readECParameter(inputStream));
                case (short) 2:
                    ECCurve f2m;
                    int readUint16 = TlsUtils.readUint16(inputStream);
                    switch (TlsUtils.readUint8(inputStream)) {
                        case (short) 1:
                            f2m = new F2m(readUint16, readECExponent(readUint16, inputStream), readECFieldElement(readUint16, inputStream), readECFieldElement(readUint16, inputStream));
                            break;
                        case (short) 2:
                            f2m = new F2m(readUint16, readECExponent(readUint16, inputStream), readECExponent(readUint16, inputStream), readECExponent(readUint16, inputStream), readECFieldElement(readUint16, inputStream), readECFieldElement(readUint16, inputStream));
                            break;
                        default:
                            throw new TlsFatalAlert((short) 47);
                    }
                    return new ECDomainParameters(f2m, deserializeECPoint(sArr, f2m, TlsUtils.readOpaque8(inputStream)), readECParameter(inputStream), readECParameter(inputStream));
                case (short) 3:
                    int readUint162 = TlsUtils.readUint16(inputStream);
                    if (!NamedCurve.refersToASpecificNamedCurve(readUint162)) {
                        throw new TlsFatalAlert((short) 47);
                    } else if (TlsProtocol.arrayContains(iArr, readUint162)) {
                        return getParametersForNamedCurve(readUint162);
                    } else {
                        throw new TlsFatalAlert((short) 47);
                    }
                default:
                    throw new TlsFatalAlert((short) 47);
            }
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 47);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static int[] readSupportedEllipticCurvesExtension(byte[] bArr) throws IOException {
        if (bArr == null) {
            throw new IllegalArgumentException("'extensionValue' cannot be null");
        }
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
        if (readUint16 < 2 || (readUint16 & 1) != 0) {
            throw new TlsFatalAlert((short) 50);
        }
        int[] readUint16Array = TlsUtils.readUint16Array(readUint16 / 2, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        return readUint16Array;
    }

    public static short[] readSupportedPointFormatsExtension(byte[] bArr) throws IOException {
        if (bArr == null) {
            throw new IllegalArgumentException("'extensionValue' cannot be null");
        }
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
        if (readUint8 < (short) 1) {
            throw new TlsFatalAlert((short) 50);
        }
        short[] readUint8Array = TlsUtils.readUint8Array(readUint8, byteArrayInputStream);
        TlsProtocol.assertEmpty(byteArrayInputStream);
        if (TlsProtocol.arrayContains(readUint8Array, (short) 0)) {
            return readUint8Array;
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static byte[] serializeECFieldElement(int i, BigInteger bigInteger) throws IOException {
        return BigIntegers.asUnsignedByteArray((i + 7) / 8, bigInteger);
    }

    public static byte[] serializeECPoint(short[] sArr, ECPoint eCPoint) throws IOException {
        ECCurve curve = eCPoint.getCurve();
        boolean z = false;
        if (curve instanceof F2m) {
            z = isCompressionPreferred(sArr, (short) 2);
        } else if (curve instanceof Fp) {
            z = isCompressionPreferred(sArr, (short) 1);
        }
        return eCPoint.getEncoded(z);
    }

    public static byte[] serializeECPublicKey(short[] sArr, ECPublicKeyParameters eCPublicKeyParameters) throws IOException {
        return serializeECPoint(sArr, eCPublicKeyParameters.getQ());
    }

    public static ECPublicKeyParameters validateECPublicKey(ECPublicKeyParameters eCPublicKeyParameters) throws IOException {
        return eCPublicKeyParameters;
    }

    public static void writeECExponent(int i, OutputStream outputStream) throws IOException {
        writeECParameter(BigInteger.valueOf((long) i), outputStream);
    }

    public static void writeECFieldElement(int i, BigInteger bigInteger, OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque8(serializeECFieldElement(i, bigInteger), outputStream);
    }

    public static void writeECParameter(BigInteger bigInteger, OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque8(BigIntegers.asUnsignedByteArray(bigInteger), outputStream);
    }

    public static void writeExplicitECParameters(short[] sArr, ECDomainParameters eCDomainParameters, OutputStream outputStream) throws IOException {
        ECCurve curve = eCDomainParameters.getCurve();
        if (curve instanceof Fp) {
            TlsUtils.writeUint8((short) 1, outputStream);
            writeECParameter(((Fp) curve).getQ(), outputStream);
        } else if (curve instanceof F2m) {
            TlsUtils.writeUint8((short) 2, outputStream);
            F2m f2m = (F2m) curve;
            TlsUtils.writeUint16(f2m.getM(), outputStream);
            if (f2m.isTrinomial()) {
                TlsUtils.writeUint8((short) 1, outputStream);
                writeECExponent(f2m.getK1(), outputStream);
            } else {
                TlsUtils.writeUint8((short) 2, outputStream);
                writeECExponent(f2m.getK1(), outputStream);
                writeECExponent(f2m.getK2(), outputStream);
                writeECExponent(f2m.getK3(), outputStream);
            }
        } else {
            throw new IllegalArgumentException("'ecParameters' not a known curve type");
        }
        writeECFieldElement(curve.getFieldSize(), curve.getA().toBigInteger(), outputStream);
        writeECFieldElement(curve.getFieldSize(), curve.getB().toBigInteger(), outputStream);
        TlsUtils.writeOpaque8(serializeECPoint(sArr, eCDomainParameters.getG()), outputStream);
        writeECParameter(eCDomainParameters.getN(), outputStream);
        writeECParameter(eCDomainParameters.getH(), outputStream);
    }

    public static void writeNamedECParameters(int i, OutputStream outputStream) throws IOException {
        if (NamedCurve.refersToASpecificNamedCurve(i)) {
            TlsUtils.writeUint8((short) 3, outputStream);
            TlsUtils.writeUint16(i, outputStream);
            return;
        }
        throw new TlsFatalAlert((short) 80);
    }
}
