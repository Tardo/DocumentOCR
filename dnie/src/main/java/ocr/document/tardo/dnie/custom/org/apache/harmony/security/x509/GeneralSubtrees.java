package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class GeneralSubtrees {
    public static final ASN1Type ASN1 = new ASN1SequenceOf(GeneralSubtree.ASN1) {
        public Object getDecodedObject(BerInputStream in) {
            return new GeneralSubtrees((List) in.content);
        }

        public Collection getValues(Object object) {
            GeneralSubtrees gss = (GeneralSubtrees) object;
            return gss.generalSubtrees == null ? new ArrayList() : gss.generalSubtrees;
        }
    };
    private byte[] encoding;
    private List generalSubtrees;

    public GeneralSubtrees(List generalSubtrees) {
        this.generalSubtrees = generalSubtrees;
    }

    public List getSubtrees() {
        return this.generalSubtrees;
    }

    public GeneralSubtrees addSubtree(GeneralSubtree subtree) {
        this.encoding = null;
        if (this.generalSubtrees == null) {
            this.generalSubtrees = new ArrayList();
        }
        this.generalSubtrees.add(subtree);
        return this;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}
