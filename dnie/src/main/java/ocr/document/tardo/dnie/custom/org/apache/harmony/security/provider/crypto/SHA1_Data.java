package custom.org.apache.harmony.security.provider.crypto;

public interface SHA1_Data {
    public static final int BYTES_OFFSET = 81;
    public static final String[] DEVICE_NAMES = new String[]{"/dev/urandom", "/dev/random"};
    public static final int DIGEST_LENGTH = 20;
    public static final int H0 = 1732584193;
    public static final int H1 = -271733879;
    public static final int H2 = -1732584194;
    public static final int H3 = 271733878;
    public static final int H4 = -1009589776;
    public static final int HASH_OFFSET = 82;
    public static final String LIBRARY_NAME = "hysecurity";
}
