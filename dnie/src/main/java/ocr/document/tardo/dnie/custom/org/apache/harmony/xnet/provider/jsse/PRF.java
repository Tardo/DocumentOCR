package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;

public class PRF {
    private static Stream logger = Logger.getStream("prf");
    protected static MessageDigest md5;
    private static Mac md5_mac;
    private static int md5_mac_length;
    protected static MessageDigest sha;
    private static Mac sha_mac;
    private static int sha_mac_length;

    private static void init() {
        try {
            md5_mac = Mac.getInstance("HmacMD5");
            sha_mac = Mac.getInstance("HmacSHA1");
            md5_mac_length = md5_mac.getMacLength();
            sha_mac_length = sha_mac.getMacLength();
            try {
                md5 = MessageDigest.getInstance("MD5");
                sha = MessageDigest.getInstance("SHA-1");
            } catch (Exception e) {
                throw new AlertException((byte) 80, new SSLException("Could not initialize the Digest Algorithms."));
            }
        } catch (NoSuchAlgorithmException e2) {
            throw new AlertException((byte) 80, new SSLException("There is no provider of HmacSHA1 or HmacMD5 algorithms installed in the system"));
        }
    }

    static synchronized void computePRF_SSLv3(byte[] out, byte[] secret, byte[] seed) {
        synchronized (PRF.class) {
            if (sha == null) {
                init();
            }
            int pos = 0;
            int iteration = 1;
            while (pos < out.length) {
                byte[] pref = new byte[iteration];
                int iteration2 = iteration + 1;
                Arrays.fill(pref, (byte) (iteration + 64));
                sha.update(pref);
                sha.update(secret);
                sha.update(seed);
                md5.update(secret);
                md5.update(sha.digest());
                byte[] digest = md5.digest();
                if (pos + 16 > out.length) {
                    System.arraycopy(digest, 0, out, pos, out.length - pos);
                    pos = out.length;
                } else {
                    System.arraycopy(digest, 0, out, pos, 16);
                    pos += 16;
                }
                iteration = iteration2;
            }
        }
    }

    static synchronized void computePRF(byte[] out, byte[] secret, byte[] str_byts, byte[] seed) throws GeneralSecurityException {
        synchronized (PRF.class) {
            SecretKeySpec keyMd5;
            SecretKeySpec keySha1;
            if (sha_mac == null) {
                init();
            }
            if (secret == null || secret.length == 0) {
                secret = new byte[8];
                keyMd5 = new SecretKeySpec(secret, "HmacMD5");
                keySha1 = new SecretKeySpec(secret, "HmacSHA1");
            } else {
                int length = secret.length >> 1;
                int offset = secret.length & 1;
                keyMd5 = new SecretKeySpec(secret, 0, length + offset, "HmacMD5");
                keySha1 = new SecretKeySpec(secret, length, length + offset, "HmacSHA1");
            }
            if (logger != null) {
                logger.println("secret[" + secret.length + "]: ");
                logger.printAsHex(16, "", " ", secret);
                logger.println("label[" + str_byts.length + "]: ");
                logger.printAsHex(16, "", " ", str_byts);
                logger.println("seed[" + seed.length + "]: ");
                logger.printAsHex(16, "", " ", seed);
                logger.println("MD5 key:");
                logger.printAsHex(16, "", " ", keyMd5.getEncoded());
                logger.println("SHA1 key:");
                logger.printAsHex(16, "", " ", keySha1.getEncoded());
            }
            md5_mac.init(keyMd5);
            sha_mac.init(keySha1);
            int pos = 0;
            md5_mac.update(str_byts);
            byte[] hash = md5_mac.doFinal(seed);
            while (pos < out.length) {
                md5_mac.update(hash);
                md5_mac.update(str_byts);
                md5_mac.update(seed);
                if (md5_mac_length + pos >= out.length) {
                    System.arraycopy(md5_mac.doFinal(), 0, out, pos, out.length - pos);
                    break;
                }
                md5_mac.doFinal(out, pos);
                pos += md5_mac_length;
                hash = md5_mac.doFinal(hash);
            }
            if (logger != null) {
                logger.println("P_MD5:");
                logger.printAsHex(md5_mac_length, "", " ", out);
            }
            sha_mac.update(str_byts);
            hash = sha_mac.doFinal(seed);
            int pos2;
            for (pos = 0; pos < out.length; pos = pos2) {
                sha_mac.update(hash);
                sha_mac.update(str_byts);
                byte[] sha1hash = sha_mac.doFinal(seed);
                int i = 0;
                pos2 = pos;
                while (true) {
                    if (((pos2 < out.length ? 1 : 0) & (i < sha_mac_length ? 1 : 0)) == 0) {
                        break;
                    }
                    pos = pos2 + 1;
                    out[pos2] = (byte) (out[pos2] ^ sha1hash[i]);
                    i++;
                    pos2 = pos;
                }
                hash = sha_mac.doFinal(hash);
            }
            if (logger != null) {
                logger.println("PRF:");
                logger.printAsHex(sha_mac_length, "", " ", out);
            }
        }
    }
}
