package custom.org.apache.harmony.security.x509.tsp;

import java.security.InvalidParameterException;

public enum PKIStatus {
    GRANTED(0),
    GRANTED_WITH_MODS(1),
    REJECTION(2),
    WAITING(3),
    REVOCATION_WARNING(4),
    REVOCATION_NOTIFICATION(5);
    
    private final int status;

    private PKIStatus(int status) {
        this.status = status;
    }

    public int getStatus() {
        return this.status;
    }

    public static PKIStatus getInstance(int status) {
        for (PKIStatus curStatus : values()) {
            if (status == curStatus.status) {
                return curStatus;
            }
        }
        throw new InvalidParameterException("Unknown PKIStatus value");
    }
}
