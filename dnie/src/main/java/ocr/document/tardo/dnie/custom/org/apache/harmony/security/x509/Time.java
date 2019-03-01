package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Choice;
import custom.org.apache.harmony.security.asn1.ASN1GeneralizedTime;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.ASN1UTCTime;
import java.util.Date;

public class Time {
    public static final ASN1Choice ASN1 = new ASN1Choice(new ASN1Type[]{ASN1GeneralizedTime.getInstance(), ASN1UTCTime.getInstance()}) {
        public int getIndex(Object object) {
            if (((Date) object).getTime() < Time.JAN_01_2050) {
                return 1;
            }
            return 0;
        }

        public Object getObjectToEncode(Object object) {
            return object;
        }
    };
    private static final long JAN_01_2050 = 2524608000000L;
}
