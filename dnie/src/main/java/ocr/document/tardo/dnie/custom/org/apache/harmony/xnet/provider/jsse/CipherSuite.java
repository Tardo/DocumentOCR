package custom.org.apache.harmony.xnet.provider.jsse;

import java.security.GeneralSecurityException;
import java.util.Hashtable;
import javax.crypto.Cipher;

public class CipherSuite {
    static int KeyExchange_DHE_DSS = 3;
    static int KeyExchange_DHE_DSS_EXPORT = 4;
    static int KeyExchange_DHE_RSA = 5;
    static int KeyExchange_DHE_RSA_EXPORT = 6;
    static int KeyExchange_DH_DSS = 7;
    static int KeyExchange_DH_DSS_EXPORT = 11;
    static int KeyExchange_DH_RSA = 8;
    static int KeyExchange_DH_RSA_EXPORT = 12;
    static int KeyExchange_DH_anon = 9;
    static int KeyExchange_DH_anon_EXPORT = 10;
    static int KeyExchange_RSA = 1;
    static int KeyExchange_RSA_EXPORT = 2;
    static CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_DHE_DSS_EXPORT, "DES40_CBC", "SHA", code_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DHE_DSS, "3DES_EDE_CBC", "SHA", code_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA = new CipherSuite("TLS_DHE_DSS_WITH_DES_CBC_SHA", false, KeyExchange_DHE_DSS, "DES_CBC", "SHA", code_TLS_DHE_DSS_WITH_DES_CBC_SHA);
    static CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_DHE_RSA_EXPORT, "DES40_CBC", "SHA", code_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DHE_RSA, "3DES_EDE_CBC", "SHA", code_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA = new CipherSuite("TLS_DHE_RSA_WITH_DES_CBC_SHA", false, KeyExchange_DHE_RSA, "DES_CBC", "SHA", code_TLS_DHE_RSA_WITH_DES_CBC_SHA);
    static CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_DH_DSS_EXPORT, "DES40_CBC", "SHA", code_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_DSS, "3DES_EDE_CBC", "SHA", code_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA = new CipherSuite("TLS_DH_DSS_WITH_DES_CBC_SHA", false, KeyExchange_DH_DSS, "DES_CBC", "SHA", code_TLS_DH_DSS_WITH_DES_CBC_SHA);
    static CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_DH_RSA_EXPORT, "DES40_CBC", "SHA", code_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_RSA, "3DES_EDE_CBC", "SHA", code_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA = new CipherSuite("TLS_DH_RSA_WITH_DES_CBC_SHA", false, KeyExchange_DH_RSA, "DES_CBC", "SHA", code_TLS_DH_RSA_WITH_DES_CBC_SHA);
    static CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_DH_anon_EXPORT, "DES40_CBC", "SHA", code_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = new CipherSuite("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", true, KeyExchange_DH_anon_EXPORT, "RC4_40", "MD5", code_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
    static CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_DH_anon, "3DES_EDE_CBC", "SHA", code_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA = new CipherSuite("TLS_DH_anon_WITH_DES_CBC_SHA", false, KeyExchange_DH_anon, "DES_CBC", "SHA", code_TLS_DH_anon_WITH_DES_CBC_SHA);
    static CipherSuite TLS_DH_anon_WITH_RC4_128_MD5 = new CipherSuite("TLS_DH_anon_WITH_RC4_128_MD5", false, KeyExchange_DH_anon, "RC4_128", "MD5", code_TLS_DH_anon_WITH_RC4_128_MD5);
    static CipherSuite TLS_NULL_WITH_NULL_NULL = new CipherSuite("TLS_NULL_WITH_NULL_NULL", true, 0, null, null, code_TLS_NULL_WITH_NULL_NULL);
    static CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = new CipherSuite("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", true, KeyExchange_RSA_EXPORT, "DES40_CBC", "SHA", code_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
    static CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = new CipherSuite("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", true, KeyExchange_RSA_EXPORT, "RC2_CBC_40", "MD5", code_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
    static CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5 = new CipherSuite("TLS_RSA_EXPORT_WITH_RC4_40_MD5", true, KeyExchange_RSA_EXPORT, "RC4_40", "MD5", code_TLS_RSA_EXPORT_WITH_RC4_40_MD5);
    static CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = new CipherSuite("TLS_RSA_WITH_3DES_EDE_CBC_SHA", false, KeyExchange_RSA, "3DES_EDE_CBC", "SHA", code_TLS_RSA_WITH_3DES_EDE_CBC_SHA);
    static CipherSuite TLS_RSA_WITH_DES_CBC_SHA = new CipherSuite("TLS_RSA_WITH_DES_CBC_SHA", false, KeyExchange_RSA, "DES_CBC", "SHA", code_TLS_RSA_WITH_DES_CBC_SHA);
    static CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA = new CipherSuite("TLS_RSA_WITH_IDEA_CBC_SHA", false, KeyExchange_RSA, "IDEA_CBC", "SHA", code_TLS_RSA_WITH_IDEA_CBC_SHA);
    static CipherSuite TLS_RSA_WITH_NULL_MD5 = new CipherSuite("TLS_RSA_WITH_NULL_MD5", true, KeyExchange_RSA, null, "MD5", code_TLS_RSA_WITH_NULL_MD5);
    static CipherSuite TLS_RSA_WITH_NULL_SHA = new CipherSuite("TLS_RSA_WITH_NULL_SHA", true, KeyExchange_RSA, null, "SHA", code_TLS_RSA_WITH_NULL_SHA);
    static CipherSuite TLS_RSA_WITH_RC4_128_MD5 = new CipherSuite("TLS_RSA_WITH_RC4_128_MD5", false, KeyExchange_RSA, "RC4_128", "MD5", code_TLS_RSA_WITH_RC4_128_MD5);
    static CipherSuite TLS_RSA_WITH_RC4_128_SHA = new CipherSuite("TLS_RSA_WITH_RC4_128_SHA", false, KeyExchange_RSA, "RC4_128", "SHA", code_TLS_RSA_WITH_RC4_128_SHA);
    static byte[] code_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, (byte) 17};
    static byte[] code_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 19};
    static byte[] code_TLS_DHE_DSS_WITH_DES_CBC_SHA = new byte[]{(byte) 0, (byte) 18};
    static byte[] code_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, Handshake.FINISHED};
    static byte[] code_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 22};
    static byte[] code_TLS_DHE_RSA_WITH_DES_CBC_SHA = new byte[]{(byte) 0, (byte) 21};
    static byte[] code_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, (byte) 11};
    static byte[] code_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 13};
    static byte[] code_TLS_DH_DSS_WITH_DES_CBC_SHA = new byte[]{(byte) 0, (byte) 12};
    static byte[] code_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, Handshake.SERVER_HELLO_DONE};
    static byte[] code_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 16};
    static byte[] code_TLS_DH_RSA_WITH_DES_CBC_SHA = new byte[]{(byte) 0, Handshake.CERTIFICATE_VERIFY};
    static byte[] code_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, (byte) 25};
    static byte[] code_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = new byte[]{(byte) 0, (byte) 23};
    static byte[] code_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 27};
    static byte[] code_TLS_DH_anon_WITH_DES_CBC_SHA = new byte[]{(byte) 0, (byte) 26};
    static byte[] code_TLS_DH_anon_WITH_RC4_128_MD5 = new byte[]{(byte) 0, (byte) 24};
    static byte[] code_TLS_NULL_WITH_NULL_NULL = new byte[]{(byte) 0, (byte) 0};
    static byte[] code_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = new byte[]{(byte) 0, (byte) 8};
    static byte[] code_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = new byte[]{(byte) 0, (byte) 6};
    static byte[] code_TLS_RSA_EXPORT_WITH_RC4_40_MD5 = new byte[]{(byte) 0, (byte) 3};
    static byte[] code_TLS_RSA_WITH_3DES_EDE_CBC_SHA = new byte[]{(byte) 0, (byte) 10};
    static byte[] code_TLS_RSA_WITH_DES_CBC_SHA = new byte[]{(byte) 0, (byte) 9};
    static byte[] code_TLS_RSA_WITH_IDEA_CBC_SHA = new byte[]{(byte) 0, (byte) 7};
    static byte[] code_TLS_RSA_WITH_NULL_MD5 = new byte[]{(byte) 0, (byte) 1};
    static byte[] code_TLS_RSA_WITH_NULL_SHA = new byte[]{(byte) 0, (byte) 2};
    static byte[] code_TLS_RSA_WITH_RC4_128_MD5 = new byte[]{(byte) 0, (byte) 4};
    static byte[] code_TLS_RSA_WITH_RC4_128_SHA = new byte[]{(byte) 0, (byte) 5};
    private static CipherSuite[] cuitesByCode = new CipherSuite[]{TLS_NULL_WITH_NULL_NULL, TLS_RSA_WITH_NULL_MD5, TLS_RSA_WITH_NULL_SHA, TLS_RSA_EXPORT_WITH_RC4_40_MD5, TLS_RSA_WITH_RC4_128_MD5, TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, TLS_RSA_WITH_IDEA_CBC_SHA, TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, TLS_RSA_WITH_DES_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_DSS_WITH_DES_CBC_SHA, TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_RSA_WITH_DES_CBC_SHA, TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA, TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_RSA_WITH_DES_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, TLS_DH_anon_WITH_RC4_128_MD5, TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_anon_WITH_DES_CBC_SHA, TLS_DH_anon_WITH_3DES_EDE_CBC_SHA};
    private static Hashtable<String, CipherSuite> cuitesByName = new Hashtable();
    static CipherSuite[] defaultCipherSuites;
    static String[] supportedCipherSuiteNames;
    static CipherSuite[] supportedCipherSuites;
    final int IVSize;
    private final int blockSize;
    final String cipherName;
    private final byte[] cipherSuiteCode;
    final int effectiveKeyBytes;
    final int expandedKeyMaterial;
    private final String hashName;
    private final int hashSize;
    private final String hmacName;
    private final boolean isExportable;
    final int keyExchange;
    final int keyMaterial;
    private final String name;
    boolean supported = true;

    static {
        int i;
        int count = 0;
        for (i = 0; i < cuitesByCode.length; i++) {
            cuitesByName.put(cuitesByCode[i].getName(), cuitesByCode[i]);
            if (cuitesByCode[i].supported) {
                count++;
            }
        }
        supportedCipherSuites = new CipherSuite[count];
        supportedCipherSuiteNames = new String[count];
        count = 0;
        for (i = 0; i < cuitesByCode.length; i++) {
            if (cuitesByCode[i].supported) {
                supportedCipherSuites[count] = cuitesByCode[i];
                supportedCipherSuiteNames[count] = supportedCipherSuites[count].getName();
                count++;
            }
        }
        CipherSuite[] defaultPretendent = new CipherSuite[]{TLS_RSA_WITH_RC4_128_MD5, TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_DES_CBC_SHA, TLS_DHE_RSA_WITH_DES_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA, TLS_RSA_EXPORT_WITH_RC4_40_MD5, TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA};
        count = 0;
        for (CipherSuite cipherSuite : defaultPretendent) {
            if (cipherSuite.supported) {
                count++;
            }
        }
        defaultCipherSuites = new CipherSuite[count];
        count = 0;
        for (i = 0; i < defaultPretendent.length; i++) {
            if (defaultPretendent[i].supported) {
                int count2 = count + 1;
                defaultCipherSuites[count] = defaultPretendent[i];
                count = count2;
            }
        }
    }

    public static CipherSuite getByName(String name) {
        return (CipherSuite) cuitesByName.get(name);
    }

    public static CipherSuite getByCode(byte b1, byte b2) {
        if (b1 == (byte) 0 && (b2 & 255) <= cuitesByCode.length) {
            return cuitesByCode[b2];
        }
        return new CipherSuite("UNKNOUN_" + b1 + "_" + b2, false, 0, "", "", new byte[]{b1, b2});
    }

    public static CipherSuite getByCode(byte b1, byte b2, byte b3) {
        if (b1 == (byte) 0 && b2 == (byte) 0 && (b3 & 255) <= cuitesByCode.length) {
            return cuitesByCode[b3];
        }
        return new CipherSuite("UNKNOUN_" + b1 + "_" + b2 + "_" + b3, false, 0, "", "", new byte[]{b1, b2, b3});
    }

    public CipherSuite(String name, boolean isExportable, int keyExchange, String cipherName, String hash, byte[] code) {
        this.name = name;
        this.keyExchange = keyExchange;
        this.isExportable = isExportable;
        if (cipherName == null) {
            this.cipherName = null;
            this.keyMaterial = 0;
            this.expandedKeyMaterial = 0;
            this.effectiveKeyBytes = 0;
            this.IVSize = 0;
            this.blockSize = 0;
        } else if ("IDEA_CBC".equals(cipherName)) {
            this.cipherName = "IDEA/CBC/NoPadding";
            this.keyMaterial = 16;
            this.expandedKeyMaterial = 16;
            this.effectiveKeyBytes = 16;
            this.IVSize = 8;
            this.blockSize = 8;
        } else if ("RC2_CBC_40".equals(cipherName)) {
            this.cipherName = "RC2/CBC/NoPadding";
            this.keyMaterial = 5;
            this.expandedKeyMaterial = 16;
            this.effectiveKeyBytes = 5;
            this.IVSize = 8;
            this.blockSize = 8;
        } else if ("RC4_40".equals(cipherName)) {
            this.cipherName = "RC4";
            this.keyMaterial = 5;
            this.expandedKeyMaterial = 16;
            this.effectiveKeyBytes = 5;
            this.IVSize = 0;
            this.blockSize = 0;
        } else if ("RC4_128".equals(cipherName)) {
            this.cipherName = "RC4";
            this.keyMaterial = 16;
            this.expandedKeyMaterial = 16;
            this.effectiveKeyBytes = 16;
            this.IVSize = 0;
            this.blockSize = 0;
        } else if ("DES40_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            this.keyMaterial = 5;
            this.expandedKeyMaterial = 8;
            this.effectiveKeyBytes = 5;
            this.IVSize = 8;
            this.blockSize = 8;
        } else if ("DES_CBC".equals(cipherName)) {
            this.cipherName = "DES/CBC/NoPadding";
            this.keyMaterial = 8;
            this.expandedKeyMaterial = 8;
            this.effectiveKeyBytes = 7;
            this.IVSize = 8;
            this.blockSize = 8;
        } else if ("3DES_EDE_CBC".equals(cipherName)) {
            this.cipherName = "DESede/CBC/NoPadding";
            this.keyMaterial = 24;
            this.expandedKeyMaterial = 24;
            this.effectiveKeyBytes = 24;
            this.IVSize = 8;
            this.blockSize = 8;
        } else {
            this.cipherName = cipherName;
            this.keyMaterial = 0;
            this.expandedKeyMaterial = 0;
            this.effectiveKeyBytes = 0;
            this.IVSize = 0;
            this.blockSize = 0;
        }
        if ("MD5".equals(hash)) {
            this.hmacName = "HmacMD5";
            this.hashName = "MD5";
            this.hashSize = 16;
        } else if ("SHA".equals(hash)) {
            this.hmacName = "HmacSHA1";
            this.hashName = "SHA-1";
            this.hashSize = 20;
        } else {
            this.hmacName = null;
            this.hashName = null;
            this.hashSize = 0;
        }
        this.cipherSuiteCode = code;
        if (this.cipherName != null) {
            try {
                Cipher.getInstance(this.cipherName);
            } catch (GeneralSecurityException e) {
                this.supported = false;
            }
        }
    }

    public boolean isAnonymous() {
        if (this.keyExchange == KeyExchange_DH_anon || this.keyExchange == KeyExchange_DH_anon_EXPORT) {
            return true;
        }
        return false;
    }

    public static CipherSuite[] getSupported() {
        return supportedCipherSuites;
    }

    public static String[] getSupportedCipherSuiteNames() {
        return (String[]) supportedCipherSuiteNames.clone();
    }

    public String getName() {
        return this.name;
    }

    public byte[] toBytes() {
        return this.cipherSuiteCode;
    }

    public String toString() {
        return this.name + ": " + this.cipherSuiteCode[0] + " " + this.cipherSuiteCode[1];
    }

    public boolean equals(Object obj) {
        if ((obj instanceof CipherSuite) && this.cipherSuiteCode[0] == ((CipherSuite) obj).cipherSuiteCode[0] && this.cipherSuiteCode[1] == ((CipherSuite) obj).cipherSuiteCode[1]) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.cipherSuiteCode[0] + this.cipherSuiteCode[1];
    }

    public String getBulkEncryptionAlgorithm() {
        return this.cipherName;
    }

    public int getBlockSize() {
        return this.blockSize;
    }

    public String getHmacName() {
        return this.hmacName;
    }

    public String getHashName() {
        return this.hashName;
    }

    public int getMACLength() {
        return this.hashSize;
    }

    public boolean isExportable() {
        return this.isExportable;
    }
}
