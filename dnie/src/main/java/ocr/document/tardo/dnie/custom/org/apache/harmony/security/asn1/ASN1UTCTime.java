package custom.org.apache.harmony.security.asn1;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class ASN1UTCTime extends ASN1Time {
    private static final ASN1UTCTime ASN1 = new ASN1UTCTime();
    public static final int UTC_HM = 11;
    public static final int UTC_HMS = 13;
    public static final int UTC_LOCAL_HM = 15;
    public static final int UTC_LOCAL_HMS = 17;
    private static final String UTC_PATTERN = "yyMMddHHmmss'Z'";

    public ASN1UTCTime() {
        super(23);
    }

    public static ASN1UTCTime getInstance() {
        return ASN1;
    }

    public Object decode(BerInputStream in) throws IOException {
        in.readUTCTime();
        if (in.isVerify) {
            return null;
        }
        return getDecodedObject(in);
    }

    public void encodeContent(BerOutputStream out) {
        out.encodeUTCTime();
    }

    public void setEncodingContent(BerOutputStream out) {
        SimpleDateFormat sdf = new SimpleDateFormat(UTC_PATTERN);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            out.content = sdf.format(out.content).getBytes("UTF-8");
            out.length = ((byte[]) out.content).length;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
