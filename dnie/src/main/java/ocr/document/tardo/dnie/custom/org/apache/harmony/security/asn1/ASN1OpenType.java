package custom.org.apache.harmony.security.asn1;

import custom.org.apache.harmony.security.x501.AttributeType;
import java.io.IOException;

public class ASN1OpenType extends ASN1Any {
    private final Id key;
    private final InformationObjectSet pool;

    public static class Id extends ASN1Oid {
        public Object decode(BerInputStream in) throws IOException {
            Object oid = super.decode(in);
            if (oid == null) {
                in.put(this, super.getDecodedObject(in));
            } else {
                in.put(this, oid);
            }
            return oid;
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            return in.get(this);
        }
    }

    public ASN1OpenType(Id key, InformationObjectSet pool) {
        this.key = key;
        this.pool = pool;
    }

    public Object decode(BerInputStream in) throws IOException {
        int[] oid = (int[]) in.get(this.key);
        if (oid == null) {
            throw new RuntimeException("");
        }
        AttributeType attr = (AttributeType) this.pool.get(oid);
        if (attr == null || !attr.type.checkTag(in.tag)) {
            in.content = (byte[]) super.getDecodedObject(in);
        } else {
            in.content = attr.type.decode(in);
        }
        return in.content;
    }

    public Object getDecodedObject(BerInputStream in) throws IOException {
        return in.content;
    }
}
