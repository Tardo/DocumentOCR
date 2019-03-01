package org.bouncycastle.crypto.tls;

import java.io.IOException;

public final class ProtocolVersion {
    public static final ProtocolVersion DTLSv10 = new ProtocolVersion(65279, "DTLS 1.0");
    public static final ProtocolVersion DTLSv12 = new ProtocolVersion(65277, "DTLS 1.2");
    public static final ProtocolVersion SSLv3 = new ProtocolVersion(768, "SSL 3.0");
    public static final ProtocolVersion TLSv10 = new ProtocolVersion(769, "TLS 1.0");
    public static final ProtocolVersion TLSv11 = new ProtocolVersion(770, "TLS 1.1");
    public static final ProtocolVersion TLSv12 = new ProtocolVersion(771, "TLS 1.2");
    private String name;
    private int version;

    private ProtocolVersion(int i, String str) {
        this.version = 65535 & i;
        this.name = str;
    }

    public static ProtocolVersion get(int i, int i2) throws IOException {
        switch (i) {
            case 3:
                switch (i2) {
                    case 0:
                        return SSLv3;
                    case 1:
                        return TLSv10;
                    case 2:
                        return TLSv11;
                    case 3:
                        return TLSv12;
                }
                break;
            case 254:
                break;
        }
        switch (i2) {
            case 253:
                return DTLSv12;
            case 255:
                return DTLSv10;
            default:
                break;
        }
        throw new TlsFatalAlert((short) 47);
    }

    public boolean equals(Object obj) {
        return this == obj;
    }

    public ProtocolVersion getEquivalentTLSVersion() {
        return !isDTLS() ? this : this == DTLSv10 ? TLSv11 : TLSv12;
    }

    public int getFullVersion() {
        return this.version;
    }

    public int getMajorVersion() {
        return this.version >> 8;
    }

    public int getMinorVersion() {
        return this.version & 255;
    }

    public int hashCode() {
        return this.version;
    }

    public boolean isDTLS() {
        return getMajorVersion() == 254;
    }

    public boolean isEqualOrEarlierVersionOf(ProtocolVersion protocolVersion) {
        boolean z = true;
        if (getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = protocolVersion.getMinorVersion() - getMinorVersion();
        if (isDTLS()) {
            if (minorVersion > 0) {
                z = false;
            }
        } else if (minorVersion < 0) {
            z = false;
        }
        return z;
    }

    public boolean isLaterVersionOf(ProtocolVersion protocolVersion) {
        boolean z = true;
        if (getMajorVersion() != protocolVersion.getMajorVersion()) {
            return false;
        }
        int minorVersion = protocolVersion.getMinorVersion() - getMinorVersion();
        if (isDTLS()) {
            if (minorVersion <= 0) {
                z = false;
            }
        } else if (minorVersion >= 0) {
            z = false;
        }
        return z;
    }

    public boolean isSSL() {
        return this == SSLv3;
    }

    public String toString() {
        return this.name;
    }
}
