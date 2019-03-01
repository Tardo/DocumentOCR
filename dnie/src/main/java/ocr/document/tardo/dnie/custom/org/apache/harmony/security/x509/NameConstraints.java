package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class NameConstraints extends ExtensionValue {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{new ASN1Implicit(0, GeneralSubtrees.ASN1), new ASN1Implicit(1, GeneralSubtrees.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new NameConstraints((GeneralSubtrees) values[0], (GeneralSubtrees) values[1], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            NameConstraints nc = (NameConstraints) object;
            values[0] = nc.permittedSubtrees;
            values[1] = nc.excludedSubtrees;
        }
    };
    private byte[] encoding;
    private final GeneralSubtrees excludedSubtrees;
    private ArrayList[] excluded_names;
    private final GeneralSubtrees permittedSubtrees;
    private ArrayList[] permitted_names;

    public NameConstraints() {
        this(null, null);
    }

    public NameConstraints(GeneralSubtrees permittedSubtrees, GeneralSubtrees excludedSubtrees) {
        if (permittedSubtrees != null) {
            List ps = permittedSubtrees.getSubtrees();
            if (ps == null || ps.size() == 0) {
                throw new IllegalArgumentException(Messages.getString("security.17D"));
            }
        }
        if (excludedSubtrees != null) {
            List es = excludedSubtrees.getSubtrees();
            if (es == null || es.size() == 0) {
                throw new IllegalArgumentException(Messages.getString("security.17E"));
            }
        }
        this.permittedSubtrees = permittedSubtrees;
        this.excludedSubtrees = excludedSubtrees;
    }

    private NameConstraints(GeneralSubtrees permittedSubtrees, GeneralSubtrees excludedSubtrees, byte[] encoding) {
        this(permittedSubtrees, excludedSubtrees);
        this.encoding = encoding;
    }

    public static NameConstraints decode(byte[] encoding) throws IOException {
        return (NameConstraints) ASN1.decode(encoding);
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    private void prepareNames() {
        int tag;
        this.permitted_names = new ArrayList[9];
        if (this.permittedSubtrees != null) {
            for (GeneralSubtree base : this.permittedSubtrees.getSubtrees()) {
                GeneralName name = base.getBase();
                tag = name.getTag();
                if (this.permitted_names[tag] == null) {
                    this.permitted_names[tag] = new ArrayList();
                }
                this.permitted_names[tag].add(name);
            }
        }
        this.excluded_names = new ArrayList[9];
        if (this.excludedSubtrees != null) {
            for (GeneralSubtree base2 : this.excludedSubtrees.getSubtrees()) {
                name = base2.getBase();
                tag = name.getTag();
                if (this.excluded_names[tag] == null) {
                    this.excluded_names[tag] = new ArrayList();
                }
                this.excluded_names[tag].add(name);
            }
        }
    }

    private byte[] getExtensionValue(X509Certificate cert, String OID) {
        try {
            byte[] bytes = cert.getExtensionValue(OID);
            if (bytes == null) {
                return null;
            }
            return (byte[]) ASN1OctetString.getInstance().decode(bytes);
        } catch (IOException e) {
            return null;
        }
    }

    public boolean isAcceptable(X509Certificate cert) {
        List names;
        if (this.permitted_names == null) {
            prepareNames();
        }
        byte[] bytes = getExtensionValue(cert, "2.5.29.17");
        if (bytes == null) {
            try {
                names = new ArrayList(1);
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }
        names = ((GeneralNames) GeneralNames.ASN1.decode(bytes)).getNames();
        if (!(this.excluded_names[4] == null && this.permitted_names[4] == null)) {
            try {
                names.add(new GeneralName(4, cert.getSubjectX500Principal().getName()));
            } catch (IOException e2) {
            }
        }
        return isAcceptable(names);
    }

    public boolean isAcceptable(List names) {
        int type;
        if (this.permitted_names == null) {
            prepareNames();
        }
        boolean[] types_presented = new boolean[9];
        boolean[] permitted_found = new boolean[9];
        for (GeneralName name : names) {
            int i;
            type = name.getTag();
            if (this.excluded_names[type] != null) {
                for (i = 0; i < this.excluded_names[type].size(); i++) {
                    if (((GeneralName) this.excluded_names[type].get(i)).isAcceptable(name)) {
                        return false;
                    }
                }
            }
            if (!(this.permitted_names[type] == null || permitted_found[type])) {
                types_presented[type] = true;
                for (i = 0; i < this.permitted_names[type].size(); i++) {
                    if (((GeneralName) this.permitted_names[type].get(i)).isAcceptable(name)) {
                        permitted_found[type] = true;
                    }
                }
            }
        }
        type = 0;
        while (type < 9) {
            if (types_presented[type] && !permitted_found[type]) {
                return false;
            }
            type++;
        }
        return true;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Name Constraints: [\n");
        if (this.permittedSubtrees != null) {
            buffer.append(prefix).append("  Permitted: [\n");
            for (GeneralSubtree dumpValue : this.permittedSubtrees.getSubtrees()) {
                dumpValue.dumpValue(buffer, prefix + "    ");
            }
            buffer.append(prefix).append("  ]\n");
        }
        if (this.excludedSubtrees != null) {
            buffer.append(prefix).append("  Excluded: [\n");
            for (GeneralSubtree dumpValue2 : this.excludedSubtrees.getSubtrees()) {
                dumpValue2.dumpValue(buffer, prefix + "    ");
            }
            buffer.append(prefix).append("  ]\n");
        }
        buffer.append('\n').append(prefix).append("]\n");
    }
}
