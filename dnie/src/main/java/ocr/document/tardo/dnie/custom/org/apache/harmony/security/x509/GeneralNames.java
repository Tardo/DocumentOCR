package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class GeneralNames {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(GeneralName.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new GeneralNames((List) in.content, in.getEncoded());
        }

        public Collection getValues(Object object) {
            return ((GeneralNames) object).generalNames;
        }
    };
    private byte[] encoding;
    private List generalNames;

    public GeneralNames() {
        this.generalNames = new ArrayList();
    }

    public GeneralNames(List generalNames) {
        this.generalNames = generalNames;
    }

    private GeneralNames(List generalNames, byte[] encoding) {
        this.generalNames = generalNames;
        this.encoding = encoding;
    }

    public List getNames() {
        if (this.generalNames == null || this.generalNames.size() == 0) {
            return null;
        }
        return new ArrayList(this.generalNames);
    }

    public List getPairsList() {
        ArrayList result = new ArrayList();
        if (this.generalNames != null) {
            for (GeneralName asList : this.generalNames) {
                result.add(asList.getAsList());
            }
        }
        return result;
    }

    public void addName(GeneralName name) {
        this.encoding = null;
        if (this.generalNames == null) {
            this.generalNames = new ArrayList();
        }
        this.generalNames.add(name);
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        if (this.generalNames != null) {
            for (Object append : this.generalNames) {
                buffer.append(prefix);
                buffer.append(append);
                buffer.append('\n');
            }
        }
    }
}
