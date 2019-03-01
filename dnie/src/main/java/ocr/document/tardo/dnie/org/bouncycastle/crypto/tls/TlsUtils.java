package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class TlsUtils {
    public static byte[] EMPTY_BYTES = new byte[0];
    public static final Integer EXT_signature_algorithms = Integers.valueOf(13);
    static final byte[][] SSL3_CONST = genConst();
    static final byte[] SSL_CLIENT = new byte[]{(byte) 67, (byte) 76, (byte) 78, (byte) 84};
    static final byte[] SSL_SERVER = new byte[]{(byte) 83, (byte) 82, (byte) 86, (byte) 82};

    public static byte[] PRF(TlsContext tlsContext, byte[] bArr, String str, byte[] bArr2, int i) {
        ProtocolVersion serverVersion = tlsContext.getServerVersion();
        if (serverVersion.isSSL()) {
            throw new IllegalStateException("No PRF available for SSLv3 session");
        }
        byte[] toByteArray = Strings.toByteArray(str);
        byte[] concat = concat(toByteArray, bArr2);
        int prfAlgorithm = tlsContext.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == 0) {
            if (!ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverVersion.getEquivalentTLSVersion())) {
                return PRF_legacy(bArr, toByteArray, concat, i);
            }
            prfAlgorithm = 1;
        }
        Digest createPRFHash = createPRFHash(prfAlgorithm);
        byte[] bArr3 = new byte[i];
        hmac_hash(createPRFHash, bArr, concat, bArr3);
        return bArr3;
    }

    static byte[] PRF_legacy(byte[] bArr, byte[] bArr2, byte[] bArr3, int i) {
        int i2 = 0;
        int length = (bArr.length + 1) / 2;
        Object obj = new byte[length];
        Object obj2 = new byte[length];
        System.arraycopy(bArr, 0, obj, 0, length);
        System.arraycopy(bArr, bArr.length - length, obj2, 0, length);
        byte[] bArr4 = new byte[i];
        byte[] bArr5 = new byte[i];
        hmac_hash(new MD5Digest(), obj, bArr3, bArr4);
        hmac_hash(new SHA1Digest(), obj2, bArr3, bArr5);
        while (i2 < i) {
            bArr4[i2] = (byte) (bArr4[i2] ^ bArr5[i2]);
            i2++;
        }
        return bArr4;
    }

    public static void addSignatureAlgorithmsExtension(Hashtable hashtable, Vector vector) throws IOException {
        hashtable.put(EXT_signature_algorithms, createSignatureAlgorithmsExtension(vector));
    }

    static byte[] calculateKeyBlock(TlsContext tlsContext, int i) {
        SecurityParameters securityParameters = tlsContext.getSecurityParameters();
        byte[] masterSecret = securityParameters.getMasterSecret();
        byte[] concat = concat(securityParameters.getServerRandom(), securityParameters.getClientRandom());
        return tlsContext.getServerVersion().isSSL() ? calculateKeyBlock_SSL(masterSecret, concat, i) : PRF(tlsContext, masterSecret, ExporterLabel.key_expansion, concat, i);
    }

    static byte[] calculateKeyBlock_SSL(byte[] bArr, byte[] bArr2, int i) {
        Digest mD5Digest = new MD5Digest();
        Digest sHA1Digest = new SHA1Digest();
        int digestSize = mD5Digest.getDigestSize();
        byte[] bArr3 = new byte[sHA1Digest.getDigestSize()];
        Object obj = new byte[(i + digestSize)];
        int i2 = 0;
        int i3 = 0;
        while (i2 < i) {
            byte[] bArr4 = SSL3_CONST[i3];
            sHA1Digest.update(bArr4, 0, bArr4.length);
            sHA1Digest.update(bArr, 0, bArr.length);
            sHA1Digest.update(bArr2, 0, bArr2.length);
            sHA1Digest.doFinal(bArr3, 0);
            mD5Digest.update(bArr, 0, bArr.length);
            mD5Digest.update(bArr3, 0, bArr3.length);
            mD5Digest.doFinal(obj, i2);
            i2 += digestSize;
            i3++;
        }
        Object obj2 = new byte[i];
        System.arraycopy(obj, 0, obj2, 0, i);
        return obj2;
    }

    static byte[] calculateMasterSecret(TlsContext tlsContext, byte[] bArr) {
        SecurityParameters securityParameters = tlsContext.getSecurityParameters();
        byte[] concat = concat(securityParameters.getClientRandom(), securityParameters.getServerRandom());
        return tlsContext.getServerVersion().isSSL() ? calculateMasterSecret_SSL(bArr, concat) : PRF(tlsContext, bArr, ExporterLabel.master_secret, concat, 48);
    }

    static byte[] calculateMasterSecret_SSL(byte[] bArr, byte[] bArr2) {
        Digest mD5Digest = new MD5Digest();
        Digest sHA1Digest = new SHA1Digest();
        int digestSize = mD5Digest.getDigestSize();
        byte[] bArr3 = new byte[sHA1Digest.getDigestSize()];
        byte[] bArr4 = new byte[(digestSize * 3)];
        int i = 0;
        for (int i2 = 0; i2 < 3; i2++) {
            byte[] bArr5 = SSL3_CONST[i2];
            sHA1Digest.update(bArr5, 0, bArr5.length);
            sHA1Digest.update(bArr, 0, bArr.length);
            sHA1Digest.update(bArr2, 0, bArr2.length);
            sHA1Digest.doFinal(bArr3, 0);
            mD5Digest.update(bArr, 0, bArr.length);
            mD5Digest.update(bArr3, 0, bArr3.length);
            mD5Digest.doFinal(bArr4, i);
            i += digestSize;
        }
        return bArr4;
    }

    static byte[] calculateVerifyData(TlsContext tlsContext, String str, byte[] bArr) {
        if (tlsContext.getServerVersion().isSSL()) {
            return bArr;
        }
        SecurityParameters securityParameters = tlsContext.getSecurityParameters();
        return PRF(tlsContext, securityParameters.getMasterSecret(), str, bArr, securityParameters.getVerifyDataLength());
    }

    public static final Digest cloneHash(int i, Digest digest) {
        switch (i) {
            case 1:
                return new MD5Digest((MD5Digest) digest);
            case 2:
                return new SHA1Digest((SHA1Digest) digest);
            case 3:
                return new SHA224Digest((SHA224Digest) digest);
            case 4:
                return new SHA256Digest((SHA256Digest) digest);
            case 5:
                return new SHA384Digest((SHA384Digest) digest);
            case 6:
                return new SHA512Digest((SHA512Digest) digest);
            default:
                throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public static final Digest clonePRFHash(int i, Digest digest) {
        switch (i) {
            case 0:
                return new CombinedHash((CombinedHash) digest);
            default:
                return cloneHash(getHashAlgorithmForPRFAlgorithm(i), digest);
        }
    }

    static byte[] concat(byte[] bArr, byte[] bArr2) {
        Object obj = new byte[(bArr.length + bArr2.length)];
        System.arraycopy(bArr, 0, obj, 0, bArr.length);
        System.arraycopy(bArr2, 0, obj, bArr.length, bArr2.length);
        return obj;
    }

    public static final Digest createHash(int i) {
        switch (i) {
            case 1:
                return new MD5Digest();
            case 2:
                return new SHA1Digest();
            case 3:
                return new SHA224Digest();
            case 4:
                return new SHA256Digest();
            case 5:
                return new SHA384Digest();
            case 6:
                return new SHA512Digest();
            default:
                throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public static final Digest createPRFHash(int i) {
        switch (i) {
            case 0:
                return new CombinedHash();
            default:
                return createHash(getHashAlgorithmForPRFAlgorithm(i));
        }
    }

    public static byte[] createSignatureAlgorithmsExtension(Vector vector) throws IOException {
        if (vector == null || vector.size() < 1 || vector.size() >= 32768) {
            throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
        }
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        writeUint16(vector.size() * 2, byteArrayOutputStream);
        for (int i = 0; i < vector.size(); i++) {
            ((SignatureAndHashAlgorithm) vector.elementAt(i)).encode(byteArrayOutputStream);
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static TlsSigner createTlsSigner(short s) {
        switch (s) {
            case (short) 1:
                return new TlsRSASigner();
            case (short) 2:
                return new TlsDSSSigner();
            case (short) 64:
                return new TlsECDSASigner();
            default:
                throw new IllegalArgumentException("'clientCertificateType' is not a type with signing capability");
        }
    }

    private static byte[][] genConst() {
        byte[][] bArr = new byte[10][];
        for (int i = 0; i < 10; i++) {
            byte[] bArr2 = new byte[(i + 1)];
            Arrays.fill(bArr2, (byte) (i + 65));
            bArr[i] = bArr2;
        }
        return bArr;
    }

    static short getClientCertificateType(Certificate certificate, Certificate certificate2) throws IOException {
        if (certificate.isEmpty()) {
            return (short) -1;
        }
        Certificate certificateAt = certificate.getCertificateAt(0);
        try {
            AsymmetricKeyParameter createKey = PublicKeyFactory.createKey(certificateAt.getSubjectPublicKeyInfo());
            if (createKey.isPrivate()) {
                throw new TlsFatalAlert((short) 80);
            } else if (createKey instanceof RSAKeyParameters) {
                validateKeyUsage(certificateAt, 128);
                return (short) 1;
            } else if (createKey instanceof DSAPublicKeyParameters) {
                validateKeyUsage(certificateAt, 128);
                return (short) 2;
            } else {
                if (createKey instanceof ECPublicKeyParameters) {
                    validateKeyUsage(certificateAt, 128);
                    return (short) 64;
                }
                throw new TlsFatalAlert((short) 43);
            }
        } catch (Exception e) {
        }
    }

    public static Vector getDefaultDSSSignatureAlgorithms() {
        return vectorOfOne(new SignatureAndHashAlgorithm((short) 2, (short) 2));
    }

    public static Vector getDefaultECDSASignatureAlgorithms() {
        return vectorOfOne(new SignatureAndHashAlgorithm((short) 2, (short) 3));
    }

    public static Vector getDefaultRSASignatureAlgorithms() {
        return vectorOfOne(new SignatureAndHashAlgorithm((short) 2, (short) 1));
    }

    public static final short getHashAlgorithmForPRFAlgorithm(int i) {
        switch (i) {
            case 0:
                throw new IllegalArgumentException("legacy PRF not a valid algorithm");
            case 1:
                return (short) 4;
            case 2:
                return (short) 5;
            default:
                throw new IllegalArgumentException("unknown PRFAlgorithm");
        }
    }

    public static ASN1ObjectIdentifier getOIDForHashAlgorithm(int i) {
        switch (i) {
            case 1:
                return PKCSObjectIdentifiers.md5;
            case 2:
                return X509ObjectIdentifiers.id_SHA1;
            case 3:
                return NISTObjectIdentifiers.id_sha224;
            case 4:
                return NISTObjectIdentifiers.id_sha256;
            case 5:
                return NISTObjectIdentifiers.id_sha384;
            case 6:
                return NISTObjectIdentifiers.id_sha512;
            default:
                throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public static Vector getSignatureAlgorithmsExtension(Hashtable hashtable) throws IOException {
        if (hashtable == null) {
            return null;
        }
        byte[] bArr = (byte[]) hashtable.get(EXT_signature_algorithms);
        return bArr == null ? null : readSignatureAlgorithmsExtension(bArr);
    }

    public static boolean hasSigningCapability(short s) {
        switch (s) {
            case (short) 1:
            case (short) 2:
            case (short) 64:
                return true;
            default:
                return false;
        }
    }

    static void hmac_hash(Digest digest, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        HMac hMac = new HMac(digest);
        CipherParameters keyParameter = new KeyParameter(bArr);
        int digestSize = digest.getDigestSize();
        int length = ((bArr3.length + digestSize) - 1) / digestSize;
        byte[] bArr4 = new byte[hMac.getMacSize()];
        Object obj = new byte[hMac.getMacSize()];
        int i = 0;
        byte[] bArr5 = bArr2;
        while (i < length) {
            hMac.init(keyParameter);
            hMac.update(bArr5, 0, bArr5.length);
            hMac.doFinal(bArr4, 0);
            hMac.init(keyParameter);
            hMac.update(bArr4, 0, bArr4.length);
            hMac.update(bArr2, 0, bArr2.length);
            hMac.doFinal(obj, 0);
            System.arraycopy(obj, 0, bArr3, digestSize * i, Math.min(digestSize, bArr3.length - (digestSize * i)));
            i++;
            bArr5 = bArr4;
        }
    }

    public static boolean isSignatureAlgorithmsExtensionAllowed(ProtocolVersion protocolVersion) {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(protocolVersion.getEquivalentTLSVersion());
    }

    public static boolean isValidUint16(int i) {
        return (65535 & i) == i;
    }

    public static boolean isValidUint24(int i) {
        return (16777215 & i) == i;
    }

    public static boolean isValidUint32(long j) {
        return (4294967295L & j) == j;
    }

    public static boolean isValidUint48(long j) {
        return (281474976710655L & j) == j;
    }

    public static boolean isValidUint64(long j) {
        return true;
    }

    public static boolean isValidUint8(short s) {
        return (s & 255) == s;
    }

    public static void readFully(byte[] bArr, InputStream inputStream) throws IOException {
        int length = bArr.length;
        if (length > 0 && length != Streams.readFully(inputStream, bArr)) {
            throw new EOFException();
        }
    }

    public static byte[] readFully(int i, InputStream inputStream) throws IOException {
        if (i < 1) {
            return EMPTY_BYTES;
        }
        byte[] bArr = new byte[i];
        if (i == Streams.readFully(inputStream, bArr)) {
            return bArr;
        }
        throw new EOFException();
    }

    public static byte[] readOpaque16(InputStream inputStream) throws IOException {
        return readFully(readUint16(inputStream), inputStream);
    }

    public static byte[] readOpaque24(InputStream inputStream) throws IOException {
        return readFully(readUint24(inputStream), inputStream);
    }

    public static byte[] readOpaque8(InputStream inputStream) throws IOException {
        return readFully(readUint8(inputStream), inputStream);
    }

    public static Vector readSignatureAlgorithmsExtension(byte[] bArr) throws IOException {
        if (bArr == null) {
            throw new IllegalArgumentException("'extensionValue' cannot be null");
        }
        InputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        int readUint16 = readUint16(byteArrayInputStream);
        if (readUint16 < 2 || (readUint16 & 1) != 0) {
            throw new TlsFatalAlert((short) 50);
        }
        int i = readUint16 / 2;
        Vector vector = new Vector(i);
        for (readUint16 = 0; readUint16 < i; readUint16++) {
            vector.addElement(SignatureAndHashAlgorithm.parse(byteArrayInputStream));
        }
        TlsProtocol.assertEmpty(byteArrayInputStream);
        return vector;
    }

    public static int readUint16(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        if (read2 >= 0) {
            return (read << 8) | read2;
        }
        throw new EOFException();
    }

    public static int readUint16(byte[] bArr, int i) {
        return ((bArr[i] & 255) << 8) | (bArr[i + 1] & 255);
    }

    public static int[] readUint16Array(int i, InputStream inputStream) throws IOException {
        int[] iArr = new int[i];
        for (int i2 = 0; i2 < i; i2++) {
            iArr[i2] = readUint16(inputStream);
        }
        return iArr;
    }

    public static int readUint24(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        int read3 = inputStream.read();
        if (read3 >= 0) {
            return ((read << 16) | (read2 << 8)) | read3;
        }
        throw new EOFException();
    }

    public static int readUint24(byte[] bArr, int i) {
        int i2 = i + 1;
        return (((bArr[i] & 255) << 16) | ((bArr[i2] & 255) << 8)) | (bArr[i2 + 1] & 255);
    }

    public static long readUint32(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        int read3 = inputStream.read();
        int read4 = inputStream.read();
        if (read4 < 0) {
            throw new EOFException();
        }
        return (((((long) read2) << 16) | (((long) read) << 24)) | (((long) read3) << 8)) | ((long) read4);
    }

    public static long readUint48(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        int read3 = inputStream.read();
        int read4 = inputStream.read();
        int read5 = inputStream.read();
        int read6 = inputStream.read();
        if (read6 < 0) {
            throw new EOFException();
        }
        return (((((((long) read2) << 32) | (((long) read) << 40)) | (((long) read3) << 24)) | (((long) read4) << 16)) | (((long) read5) << 8)) | ((long) read6);
    }

    public static long readUint48(byte[] bArr, int i) {
        return (((long) readUint24(bArr, i + 3)) & 4294967295L) | ((((long) readUint24(bArr, i)) & 4294967295L) << 24);
    }

    public static short readUint8(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        if (read >= 0) {
            return (short) read;
        }
        throw new EOFException();
    }

    public static short readUint8(byte[] bArr, int i) {
        return (short) bArr[i];
    }

    public static short[] readUint8Array(int i, InputStream inputStream) throws IOException {
        short[] sArr = new short[i];
        for (int i2 = 0; i2 < i; i2++) {
            sArr[i2] = readUint8(inputStream);
        }
        return sArr;
    }

    public static ProtocolVersion readVersion(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        if (read2 >= 0) {
            return ProtocolVersion.get(read, read2);
        }
        throw new EOFException();
    }

    public static ProtocolVersion readVersion(byte[] bArr, int i) throws IOException {
        return ProtocolVersion.get(bArr[i] & 255, bArr[i + 1] & 255);
    }

    public static int readVersionRaw(InputStream inputStream) throws IOException {
        int read = inputStream.read();
        int read2 = inputStream.read();
        if (read2 >= 0) {
            return (read << 8) | read2;
        }
        throw new EOFException();
    }

    static void validateKeyUsage(Certificate certificate, int i) throws IOException {
        Extensions extensions = certificate.getTBSCertificate().getExtensions();
        if (extensions != null) {
            KeyUsage fromExtensions = KeyUsage.fromExtensions(extensions);
            if (fromExtensions != null && ((fromExtensions.getBytes()[0] & 255) & i) != i) {
                throw new TlsFatalAlert((short) 46);
            }
        }
    }

    private static Vector vectorOfOne(Object obj) {
        Vector vector = new Vector(1);
        vector.addElement(obj);
        return vector;
    }

    public static void writeGMTUnixTime(byte[] bArr, int i) {
        int currentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        bArr[i] = (byte) (currentTimeMillis >> 24);
        bArr[i + 1] = (byte) (currentTimeMillis >> 16);
        bArr[i + 2] = (byte) (currentTimeMillis >> 8);
        bArr[i + 3] = (byte) currentTimeMillis;
    }

    public static void writeOpaque16(byte[] bArr, OutputStream outputStream) throws IOException {
        writeUint16(bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeOpaque24(byte[] bArr, OutputStream outputStream) throws IOException {
        writeUint24(bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeOpaque8(byte[] bArr, OutputStream outputStream) throws IOException {
        writeUint8((short) bArr.length, outputStream);
        outputStream.write(bArr);
    }

    public static void writeUint16(int i, OutputStream outputStream) throws IOException {
        outputStream.write(i >> 8);
        outputStream.write(i);
    }

    public static void writeUint16(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) (i >> 8);
        bArr[i2 + 1] = (byte) i;
    }

    public static void writeUint16Array(int[] iArr, OutputStream outputStream) throws IOException {
        for (int writeUint16 : iArr) {
            writeUint16(writeUint16, outputStream);
        }
    }

    public static void writeUint24(int i, OutputStream outputStream) throws IOException {
        outputStream.write(i >> 16);
        outputStream.write(i >> 8);
        outputStream.write(i);
    }

    public static void writeUint24(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) (i >> 16);
        bArr[i2 + 1] = (byte) (i >> 8);
        bArr[i2 + 2] = (byte) i;
    }

    public static void writeUint32(long j, OutputStream outputStream) throws IOException {
        outputStream.write((int) (j >> 24));
        outputStream.write((int) (j >> 16));
        outputStream.write((int) (j >> 8));
        outputStream.write((int) j);
    }

    public static void writeUint32(long j, byte[] bArr, int i) {
        bArr[i] = (byte) ((int) (j >> 24));
        bArr[i + 1] = (byte) ((int) (j >> 16));
        bArr[i + 2] = (byte) ((int) (j >> 8));
        bArr[i + 3] = (byte) ((int) j);
    }

    public static void writeUint48(long j, byte[] bArr, int i) {
        bArr[i] = (byte) ((int) (j >> 40));
        bArr[i + 1] = (byte) ((int) (j >> 32));
        bArr[i + 2] = (byte) ((int) (j >> 24));
        bArr[i + 3] = (byte) ((int) (j >> 16));
        bArr[i + 4] = (byte) ((int) (j >> 8));
        bArr[i + 5] = (byte) ((int) j);
    }

    public static void writeUint64(long j, OutputStream outputStream) throws IOException {
        outputStream.write((int) (j >> 56));
        outputStream.write((int) (j >> 48));
        outputStream.write((int) (j >> 40));
        outputStream.write((int) (j >> 32));
        outputStream.write((int) (j >> 24));
        outputStream.write((int) (j >> 16));
        outputStream.write((int) (j >> 8));
        outputStream.write((int) j);
    }

    public static void writeUint64(long j, byte[] bArr, int i) {
        bArr[i] = (byte) ((int) (j >> 56));
        bArr[i + 1] = (byte) ((int) (j >> 48));
        bArr[i + 2] = (byte) ((int) (j >> 40));
        bArr[i + 3] = (byte) ((int) (j >> 32));
        bArr[i + 4] = (byte) ((int) (j >> 24));
        bArr[i + 5] = (byte) ((int) (j >> 16));
        bArr[i + 6] = (byte) ((int) (j >> 8));
        bArr[i + 7] = (byte) ((int) j);
    }

    public static void writeUint8(short s, OutputStream outputStream) throws IOException {
        outputStream.write(s);
    }

    public static void writeUint8(short s, byte[] bArr, int i) {
        bArr[i] = (byte) s;
    }

    public static void writeUint8Array(short[] sArr, OutputStream outputStream) throws IOException {
        for (short writeUint8 : sArr) {
            writeUint8(writeUint8, outputStream);
        }
    }

    public static void writeVersion(ProtocolVersion protocolVersion, OutputStream outputStream) throws IOException {
        outputStream.write(protocolVersion.getMajorVersion());
        outputStream.write(protocolVersion.getMinorVersion());
    }

    public static void writeVersion(ProtocolVersion protocolVersion, byte[] bArr, int i) throws IOException {
        bArr[i] = (byte) protocolVersion.getMajorVersion();
        bArr[i + 1] = (byte) protocolVersion.getMinorVersion();
    }
}
