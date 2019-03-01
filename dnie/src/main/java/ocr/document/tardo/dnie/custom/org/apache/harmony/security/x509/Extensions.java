package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class Extensions {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(Extension.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new Extensions((List) in.content);
        }

        public Collection getValues(Object object) {
            Extensions exts = (Extensions) object;
            return exts.extensions == null ? new ArrayList() : exts.extensions;
        }
    };
    private static List SUPPORTED_CRITICAL = Arrays.asList(new String[]{"2.5.29.15", "2.5.29.19", "2.5.29.32", "2.5.29.17", "2.5.29.30", "2.5.29.36", "2.5.29.37", "2.5.29.54"});
    private Set critical;
    private byte[] encoding;
    private List<Extension> extensions;
    private boolean hasUnsupported;
    private Set noncritical;
    private HashMap oidMap;

    public Extensions(List extensions) {
        this.extensions = extensions;
    }

    public List getExtensions() {
        return this.extensions;
    }

    public int size() {
        return this.extensions == null ? 0 : this.extensions.size();
    }

    public Set getCriticalExtensions() {
        if (this.critical == null) {
            makeOidsLists();
        }
        return this.critical;
    }

    public Set getNonCriticalExtensions() {
        if (this.noncritical == null) {
            makeOidsLists();
        }
        return this.noncritical;
    }

    public boolean hasUnsupportedCritical() {
        if (this.critical == null) {
            makeOidsLists();
        }
        return this.hasUnsupported;
    }

    private void makeOidsLists() {
        if (this.extensions != null) {
            int size = this.extensions.size();
            this.critical = new HashSet(size);
            this.noncritical = new HashSet(size);
            for (int i = 0; i < size; i++) {
                Extension extn = (Extension) this.extensions.get(i);
                String oid = extn.getExtnID();
                if (extn.getCritical()) {
                    if (!SUPPORTED_CRITICAL.contains(oid)) {
                        this.hasUnsupported = true;
                    }
                    this.critical.add(oid);
                } else {
                    this.noncritical.add(oid);
                }
            }
        }
    }

    public Extension getExtensionByOID(String oid) {
        if (this.extensions == null) {
            return null;
        }
        if (this.oidMap == null) {
            this.oidMap = new HashMap();
            for (Extension extn : this.extensions) {
                this.oidMap.put(extn.getExtnID(), extn);
            }
        }
        return (Extension) this.oidMap.get(oid);
    }

    public boolean[] valueOfKeyUsage() {
        Extension extn = getExtensionByOID("2.5.29.15");
        if (extn != null) {
            KeyUsage kUsage = extn.getKeyUsageValue();
            if (kUsage != null) {
                return kUsage.getKeyUsage();
            }
        }
        return null;
    }

    public List valueOfExtendedKeyUsage() throws IOException {
        Extension extn = getExtensionByOID("2.5.29.37");
        if (extn == null) {
            return null;
        }
        return ((ExtendedKeyUsage) extn.getDecodedExtensionValue()).getExtendedKeyUsage();
    }

    public int valueOfBasicConstrains() {
        Extension extn = getExtensionByOID("2.5.29.19");
        if (extn != null) {
            BasicConstraints bc = extn.getBasicConstraintsValue();
            if (bc != null) {
                return bc.getPathLenConstraint();
            }
        }
        return Integer.MAX_VALUE;
    }

    public List valueOfSubjectAlternativeName() throws IOException {
        Extension extn = getExtensionByOID("2.5.29.17");
        if (extn == null) {
            return null;
        }
        return ((GeneralNames) GeneralNames.ASN1.decode(extn.getExtnValue())).getPairsList();
    }

    public List valueOfIssuerAlternativeName() throws IOException {
        Extension extn = getExtensionByOID("2.5.29.18");
        if (extn == null) {
            return null;
        }
        return ((GeneralNames) GeneralNames.ASN1.decode(extn.getExtnValue())).getPairsList();
    }

    public X500Principal valueOfCertificateIssuerExtension() throws IOException {
        Extension extn = getExtensionByOID("2.5.29.29");
        if (extn == null) {
            return null;
        }
        return ((CertificateIssuer) extn.getDecodedExtensionValue()).getIssuer();
    }

    public void addExtension(Extension extn) {
        this.encoding = null;
        if (this.extensions == null) {
            this.extensions = new ArrayList();
        }
        this.extensions.add(extn);
        if (this.oidMap != null) {
            this.oidMap.put(extn.getExtnID(), extn);
        }
        if (this.critical != null) {
            String oid = extn.getExtnID();
            if (extn.getCritical()) {
                if (!SUPPORTED_CRITICAL.contains(oid)) {
                    this.hasUnsupported = true;
                }
                this.critical.add(oid);
                return;
            }
            this.noncritical.add(oid);
        }
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public boolean equals(Object exts) {
        boolean z = true;
        if (!(exts instanceof Extensions)) {
            return false;
        }
        Extensions extns = (Extensions) exts;
        if (this.extensions == null || this.extensions.size() == 0) {
            if (!(extns.extensions == null || extns.extensions.size() == 0)) {
                z = false;
            }
        } else if (extns.extensions == null || extns.extensions.size() == 0) {
            z = false;
        } else if (!(this.extensions.containsAll(extns.extensions) && this.extensions.size() == extns.extensions.size())) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        if (this.extensions != null) {
            return this.extensions.hashCode();
        }
        return 0;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        if (this.extensions != null) {
            int num = 1;
            for (Extension extension : this.extensions) {
                int num2 = num + 1;
                buffer.append('\n').append(prefix).append('[').append(num).append("]: ");
                extension.dumpValue(buffer, prefix);
                num = num2;
            }
        }
    }
}
