package es.gob.jmulticard.asn1.der.pkcs1;

import custom.org.apache.harmony.xnet.provider.jsse.Handshake;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.asn1.der.OctectString;
import es.gob.jmulticard.asn1.der.Sequence;
import java.io.IOException;

public final class DigestInfo extends Sequence {
    private static final byte[] MD2_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 32, (byte) 48, (byte) 12, (byte) 6, (byte) 8, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 2, (byte) 2, (byte) 5, (byte) 0, (byte) 4, (byte) 16};
    public static final byte[] MD5_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 32, (byte) 48, (byte) 12, (byte) 6, (byte) 8, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 2, (byte) 5, (byte) 5, (byte) 0, (byte) 4, (byte) 16};
    private static final String NONEWITHRSA_NORMALIZED_ALGO_NAME = "NONEwithRSA";
    private static final String NONE_NORMALIZED_ALGO_NAME = "NONE";
    private static final String SHA1WITHRSA_NORMALIZED_ALGO_NAME = "SHA1withRSA";
    private static final byte[] SHA1_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 33, (byte) 48, (byte) 9, (byte) 6, (byte) 5, (byte) 43, Handshake.SERVER_HELLO_DONE, (byte) 3, (byte) 2, (byte) 26, (byte) 5, (byte) 0, (byte) 4, Handshake.FINISHED};
    private static final String SHA1_NORMALIZED_ALGO_NAME = "SHA-1";
    private static final String SHA256WITHRSA_NORMALIZED_ALGO_NAME = "SHA256withRSA";
    private static final byte[] SHA256_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 49, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 96, (byte) -122, (byte) 72, (byte) 1, (byte) 101, (byte) 3, (byte) 4, (byte) 2, (byte) 1, (byte) 5, (byte) 0, (byte) 4, (byte) 32};
    private static final String SHA256_NORMALIZED_ALGO_NAME = "SHA-256";
    private static final String SHA384WITHRSA_NORMALIZED_ALGO_NAME = "SHA384withRSA";
    private static final byte[] SHA384_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 65, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 96, (byte) -122, (byte) 72, (byte) 1, (byte) 101, (byte) 3, (byte) 4, (byte) 2, (byte) 2, (byte) 5, (byte) 0, (byte) 4, (byte) 48};
    private static final String SHA384_NORMALIZED_ALGO_NAME = "SHA-384";
    private static final String SHA512WITHRSA_NORMALIZED_ALGO_NAME = "SHA512withRSA";
    private static final byte[] SHA512_DIGESTINFO_HEADER = new byte[]{(byte) 48, (byte) 81, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 96, (byte) -122, (byte) 72, (byte) 1, (byte) 101, (byte) 3, (byte) 4, (byte) 2, (byte) 3, (byte) 5, (byte) 0, (byte) 4, (byte) 64};
    private static final String SHA512_NORMALIZED_ALGO_NAME = "SHA-512";

    protected static byte[] getSha1DigestinfoHeader() {
        byte[] out = new byte[SHA1_DIGESTINFO_HEADER.length];
        System.arraycopy(SHA1_DIGESTINFO_HEADER, 0, out, 0, SHA1_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getSha256DigestinfoHeader() {
        byte[] out = new byte[SHA256_DIGESTINFO_HEADER.length];
        System.arraycopy(SHA256_DIGESTINFO_HEADER, 0, out, 0, SHA256_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getSha384DigestinfoHeader() {
        byte[] out = new byte[SHA384_DIGESTINFO_HEADER.length];
        System.arraycopy(SHA384_DIGESTINFO_HEADER, 0, out, 0, SHA384_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getSha512DigestinfoHeader() {
        byte[] out = new byte[SHA512_DIGESTINFO_HEADER.length];
        System.arraycopy(SHA512_DIGESTINFO_HEADER, 0, out, 0, SHA512_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getMd2DigestinfoHeader() {
        byte[] out = new byte[MD2_DIGESTINFO_HEADER.length];
        System.arraycopy(MD2_DIGESTINFO_HEADER, 0, out, 0, MD2_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getMd5DigestinfoHeader() {
        byte[] out = new byte[MD5_DIGESTINFO_HEADER.length];
        System.arraycopy(MD5_DIGESTINFO_HEADER, 0, out, 0, MD5_DIGESTINFO_HEADER.length);
        return out;
    }

    protected static byte[] getNoneDigestinfoHeader() {
        return new byte[0];
    }

    public DigestInfo() {
        super(new Class[]{AlgorithmIdentifer.class, OctectString.class});
    }

    public static byte[] encode(String signingAlgorithm, byte[] data, CryptoHelper cryptoHelper) throws IOException {
        String digestAlgorithm = getDigestAlgorithm(getNormalizedSigningAlgorithm(signingAlgorithm));
        byte[] header = selectHeaderTemplate(digestAlgorithm);
        byte[] md = cryptoHelper.digest(digestAlgorithm, data);
        byte[] digestInfo = new byte[(header.length + md.length)];
        System.arraycopy(header, 0, digestInfo, 0, header.length);
        System.arraycopy(md, 0, digestInfo, header.length, md.length);
        return digestInfo;
    }

    private static String getNormalizedSigningAlgorithm(String algorithm) {
        if ("SHA1withRSA".equalsIgnoreCase(algorithm) || "SHAwithRSA".equalsIgnoreCase(algorithm) || "SHA-1withRSA".equalsIgnoreCase(algorithm) || "SHA1withRSAEncryption".equalsIgnoreCase(algorithm) || "SHA-1withRSAEncryption".equalsIgnoreCase(algorithm)) {
            return "SHA1withRSA";
        }
        if (SHA256WITHRSA_NORMALIZED_ALGO_NAME.equalsIgnoreCase(algorithm) || "SHA-256withRSA".equalsIgnoreCase(algorithm) || "SHA-256withRSAEncryption".equalsIgnoreCase(algorithm) || "SHA256withRSAEncryption".equalsIgnoreCase(algorithm)) {
            return SHA256WITHRSA_NORMALIZED_ALGO_NAME;
        }
        if (SHA384WITHRSA_NORMALIZED_ALGO_NAME.equalsIgnoreCase(algorithm) || "SHA-384withRSA".equalsIgnoreCase(algorithm) || "SHA-384withRSAEncryption".equalsIgnoreCase(algorithm) || "SHA384withRSAEncryption".equalsIgnoreCase(algorithm)) {
            return SHA384WITHRSA_NORMALIZED_ALGO_NAME;
        }
        if (SHA512WITHRSA_NORMALIZED_ALGO_NAME.equalsIgnoreCase(algorithm) || "SHA-512withRSA".equalsIgnoreCase(algorithm) || "SHA-512withRSAEncryption".equalsIgnoreCase(algorithm) || "SHA512withRSAEncryption".equalsIgnoreCase(algorithm)) {
            return SHA512WITHRSA_NORMALIZED_ALGO_NAME;
        }
        if (NONEWITHRSA_NORMALIZED_ALGO_NAME.equalsIgnoreCase(algorithm) || "NONEwithRSAEncryption".equalsIgnoreCase(algorithm)) {
            return NONEWITHRSA_NORMALIZED_ALGO_NAME;
        }
        return algorithm;
    }

    private static byte[] selectHeaderTemplate(String algorithm) {
        if (SHA1_NORMALIZED_ALGO_NAME.equals(algorithm)) {
            return getSha1DigestinfoHeader();
        }
        if (SHA256_NORMALIZED_ALGO_NAME.equals(algorithm)) {
            return getSha256DigestinfoHeader();
        }
        if (SHA384_NORMALIZED_ALGO_NAME.equals(algorithm)) {
            return getSha384DigestinfoHeader();
        }
        if (SHA512_NORMALIZED_ALGO_NAME.equals(algorithm)) {
            return getSha512DigestinfoHeader();
        }
        if (NONE_NORMALIZED_ALGO_NAME.equals(algorithm)) {
            return getNoneDigestinfoHeader();
        }
        return new byte[0];
    }

    private static String getDigestAlgorithm(String signatureAlgorithm) {
        if ("SHA1withRSA".equals(signatureAlgorithm)) {
            return SHA1_NORMALIZED_ALGO_NAME;
        }
        if (SHA256WITHRSA_NORMALIZED_ALGO_NAME.equals(signatureAlgorithm)) {
            return SHA256_NORMALIZED_ALGO_NAME;
        }
        if (SHA384WITHRSA_NORMALIZED_ALGO_NAME.equals(signatureAlgorithm)) {
            return SHA384_NORMALIZED_ALGO_NAME;
        }
        if (SHA512WITHRSA_NORMALIZED_ALGO_NAME.equals(signatureAlgorithm)) {
            return SHA512_NORMALIZED_ALGO_NAME;
        }
        if (NONEWITHRSA_NORMALIZED_ALGO_NAME.equals(signatureAlgorithm)) {
            return NONE_NORMALIZED_ALGO_NAME;
        }
        return signatureAlgorithm;
    }
}
