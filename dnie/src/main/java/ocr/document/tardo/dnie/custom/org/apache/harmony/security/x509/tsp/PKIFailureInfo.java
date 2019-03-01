package custom.org.apache.harmony.security.x509.tsp;

import java.security.InvalidParameterException;

public enum PKIFailureInfo {
    BAD_ALG(0),
    BAD_REQUEST(2),
    BAD_DATA_FORMAT(5),
    TIME_NOT_AVAILABLE(14),
    UNACCEPTED_POLICY(15),
    UNACCEPTED_EXTENSION(16),
    ADD_INFO_NOT_AVAILABLE(17),
    SYSTEM_FAILURE(25);
    
    private static int maxValue;
    private final int value;

    private PKIFailureInfo(int value) {
        this.value = value;
    }

    public int getValue() {
        return this.value;
    }

    public static int getMaxValue() {
        if (maxValue == 0) {
            for (PKIFailureInfo cur : values()) {
                if (cur.value > maxValue) {
                    maxValue = cur.value;
                }
            }
        }
        return maxValue;
    }

    public static PKIFailureInfo getInstance(int value) {
        for (PKIFailureInfo info : values()) {
            if (value == info.value) {
                return info;
            }
        }
        throw new InvalidParameterException("Unknown PKIFailureInfo value");
    }
}
