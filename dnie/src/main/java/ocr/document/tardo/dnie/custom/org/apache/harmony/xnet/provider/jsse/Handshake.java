package custom.org.apache.harmony.xnet.provider.jsse;

public class Handshake {
    public static final byte CERTIFICATE = (byte) 11;
    public static final byte CERTIFICATE_REQUEST = (byte) 13;
    public static final byte CERTIFICATE_VERIFY = (byte) 15;
    public static final byte CLIENT_HELLO = (byte) 1;
    public static final byte CLIENT_KEY_EXCHANGE = (byte) 16;
    public static final byte FINISHED = (byte) 20;
    public static final byte HELLO_REQUEST = (byte) 0;
    public static final byte SERVER_HELLO = (byte) 2;
    public static final byte SERVER_HELLO_DONE = (byte) 14;
    public static final byte SERVER_KEY_EXCHANGE = (byte) 12;
}
