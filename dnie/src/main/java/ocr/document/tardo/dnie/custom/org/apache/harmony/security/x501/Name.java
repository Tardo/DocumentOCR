package custom.org.apache.harmony.security.x501;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.DerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.x509.DNParser;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;

public class Name {
    public static final ASN1SequenceOf ASN1 = new ASN1SequenceOf(ASN1_RDN) {
        public Object getDecodedObject(BerInputStream in) {
            return new Name((List) in.content);
        }

        public Collection getValues(Object object) {
            return ((Name) object).rdn;
        }
    };
    public static final ASN1SetOf ASN1_RDN = new ASN1SetOf(AttributeTypeAndValue.ASN1);
    private String canonicalString;
    private volatile byte[] encoded;
    private List rdn;
    private String rfc1779String;
    private String rfc2253String;

    public Name(byte[] encoding) throws IOException {
        DerInputStream in = new DerInputStream(encoding);
        if (in.getEndOffset() != encoding.length) {
            throw new IOException(Messages.getString("security.111"));
        }
        ASN1.decode(in);
        this.rdn = (List) in.content;
    }

    public Name(String name) throws IOException {
        this.rdn = new DNParser(name).parse();
    }

    private Name(List rdn) {
        this.rdn = rdn;
    }

    public X500Principal getX500Principal() {
        return new X500Principal(getName0("RFC2253"));
    }

    public String getName(String format) {
        if ("RFC1779".equals(format)) {
            if (this.rfc1779String == null) {
                this.rfc1779String = getName0(format);
            }
            return this.rfc1779String;
        } else if ("RFC2253".equals(format)) {
            if (this.rfc2253String == null) {
                this.rfc2253String = getName0(format);
            }
            return this.rfc2253String;
        } else if ("CANONICAL".equals(format)) {
            if (this.canonicalString == null) {
                this.canonicalString = getName0(format);
            }
            return this.canonicalString;
        } else if ("RFC1779".equalsIgnoreCase(format)) {
            if (this.rfc1779String == null) {
                this.rfc1779String = getName0("RFC1779");
            }
            return this.rfc1779String;
        } else if ("RFC2253".equalsIgnoreCase(format)) {
            if (this.rfc2253String == null) {
                this.rfc2253String = getName0("RFC2253");
            }
            return this.rfc2253String;
        } else if ("CANONICAL".equalsIgnoreCase(format)) {
            if (this.canonicalString == null) {
                this.canonicalString = getName0("CANONICAL");
            }
            return this.canonicalString;
        } else {
            throw new IllegalArgumentException(Messages.getString("security.177", (Object) format));
        }
    }

    private String getName0(String format) {
        StringBuffer name = new StringBuffer();
        for (int i = this.rdn.size() - 1; i >= 0; i--) {
            List atavList = (List) this.rdn.get(i);
            if ("CANONICAL" == format) {
                List sortedList = new LinkedList(atavList);
                Collections.sort(sortedList, new AttributeTypeAndValueComparator());
                atavList = sortedList;
            }
            Iterator it = atavList.iterator();
            while (it.hasNext()) {
                ((AttributeTypeAndValue) it.next()).appendName(format, name);
                if (it.hasNext()) {
                    if ("RFC1779" == format) {
                        name.append(" + ");
                    } else {
                        name.append('+');
                    }
                }
            }
            if (i != 0) {
                name.append(',');
                if (format == "RFC1779") {
                    name.append(' ');
                }
            }
        }
        String sName = name.toString();
        if ("CANONICAL".equals(format)) {
            return sName.toLowerCase(Locale.US);
        }
        return sName;
    }

    public byte[] getEncoded() {
        if (this.encoded == null) {
            this.encoded = ASN1.encode(this);
        }
        return this.encoded;
    }
}
