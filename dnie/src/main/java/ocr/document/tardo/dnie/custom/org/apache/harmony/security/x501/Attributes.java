package custom.org.apache.harmony.security.x501;

import custom.org.apache.harmony.security.asn1.ASN1OpenType;
import custom.org.apache.harmony.security.asn1.ASN1OpenType.Id;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.InformationObjectSet;

public class Attributes {
    public static ASN1Sequence getASN1(InformationObjectSet set) {
        ASN1OpenType any = new ASN1OpenType(new Id(), set);
        return new ASN1Sequence(new ASN1Type[]{id, new ASN1SetOf(any)});
    }
}
