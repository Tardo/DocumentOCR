package custom.org.apache.harmony.xnet.provider.jsse;

import java.util.Hashtable;

public class ProtocolVersion {
    public static final ProtocolVersion SSLv3 = new ProtocolVersion("SSLv3", new byte[]{(byte) 3, (byte) 0});
    public static final ProtocolVersion TLSv1 = new ProtocolVersion("TLSv1", new byte[]{(byte) 3, (byte) 1});
    private static Hashtable<String, ProtocolVersion> protocolsByName = new Hashtable(4);
    public static final String[] supportedProtocols = new String[]{"TLSv1", "SSLv3"};
    public final String name;
    public final byte[] version;

    static {
        protocolsByName.put(SSLv3.name, SSLv3);
        protocolsByName.put(TLSv1.name, TLSv1);
        protocolsByName.put("SSL", SSLv3);
        protocolsByName.put("TLS", TLSv1);
    }

    public static boolean isSupported(byte[] version) {
        return version[0] == (byte) 3 && (version[1] == (byte) 0 || version[1] == (byte) 1);
    }

    public static ProtocolVersion getByVersion(byte[] version) {
        if (version[0] == (byte) 3) {
            if (version[1] == (byte) 1) {
                return TLSv1;
            }
            if (version[1] == (byte) 0) {
                return SSLv3;
            }
        }
        return null;
    }

    public static boolean isSupported(String name) {
        return protocolsByName.containsKey(name);
    }

    public static ProtocolVersion getByName(String name) {
        return (ProtocolVersion) protocolsByName.get(name);
    }

    public static ProtocolVersion getLatestVersion(String[] protocols) {
        if (protocols == null || protocols.length == 0) {
            return null;
        }
        ProtocolVersion latest = getByName(protocols[0]);
        for (int i = 1; i < protocols.length; i++) {
            ProtocolVersion current = getByName(protocols[i]);
            if (current != null && (latest == null || latest.version[0] < current.version[0] || (latest.version[0] == current.version[0] && latest.version[1] < current.version[1]))) {
                latest = current;
            }
        }
        return latest;
    }

    private ProtocolVersion(String name, byte[] version) {
        this.name = name;
        this.version = version;
    }

    public boolean equals(Object o) {
        if ((o instanceof ProtocolVersion) && this.version[0] == ((ProtocolVersion) o).version[0] && this.version[1] == ((ProtocolVersion) o).version[1]) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.version[0] + this.version[1];
    }
}
