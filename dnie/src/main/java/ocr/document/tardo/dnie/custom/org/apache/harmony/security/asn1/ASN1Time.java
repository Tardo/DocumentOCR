package custom.org.apache.harmony.security.asn1;

import java.io.IOException;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public abstract class ASN1Time extends ASN1StringType {
    public ASN1Time(int tagNumber) {
        super(tagNumber);
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        GregorianCalendar c = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        c.set(1, in.times[0]);
        c.set(2, in.times[1] - 1);
        c.set(5, in.times[2]);
        c.set(11, in.times[3]);
        c.set(12, in.times[4]);
        c.set(13, in.times[5]);
        c.set(14, in.times[6]);
        return c.getTime();
    }
}
