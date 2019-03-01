package custom.org.apache.harmony.security.x501;

import custom.org.apache.harmony.security.Util;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1StringType;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BerOutputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.utils.ObjectIdentifier;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashMap;

public class AttributeTypeAndValue {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Oid.getInstance(), attributeValue}) {
        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            return new AttributeTypeAndValue((int[]) values[0], (AttributeValue) values[1]);
        }

        protected void getValues(Object object, Object[] values) {
            AttributeTypeAndValue atav = (AttributeTypeAndValue) object;
            values[0] = atav.oid.getOid();
            values[1] = atav.value;
        }
    };
    /* renamed from: C */
    private static final ObjectIdentifier f16C = new ObjectIdentifier(new int[]{2, 5, 4, 6}, "C", RFC1779_NAMES);
    private static final int CAPACITY = 10;
    private static final ObjectIdentifier CN = new ObjectIdentifier(new int[]{2, 5, 4, 3}, "CN", RFC1779_NAMES);
    private static final ObjectIdentifier DC = new ObjectIdentifier(new int[]{0, 9, 2342, 19200300, 100, 1, 25}, "DC", RFC2253_NAMES);
    private static final ObjectIdentifier DNQ = new ObjectIdentifier(new int[]{2, 5, 4, 46}, "DNQ", RFC2459_NAMES);
    private static final ObjectIdentifier DNQUALIFIER = new ObjectIdentifier(new int[]{2, 5, 4, 46}, "DNQUALIFIER", RFC2459_NAMES);
    private static final ObjectIdentifier EMAILADDRESS = new ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 9, 1}, "EMAILADDRESS", RFC2459_NAMES);
    private static final ObjectIdentifier GENERATION = new ObjectIdentifier(new int[]{2, 5, 4, 44}, "GENERATION", RFC2459_NAMES);
    private static final ObjectIdentifier GIVENNAME = new ObjectIdentifier(new int[]{2, 5, 4, 42}, "GIVENNAME", RFC2459_NAMES);
    private static final ObjectIdentifier INITIALS = new ObjectIdentifier(new int[]{2, 5, 4, 43}, "INITIALS", RFC2459_NAMES);
    private static final HashMap KNOWN_NAMES = new HashMap(30);
    private static final ObjectIdentifier[][] KNOWN_OIDS = ((ObjectIdentifier[][]) Array.newInstance(ObjectIdentifier.class, new int[]{SIZE, CAPACITY}));
    /* renamed from: L */
    private static final ObjectIdentifier f17L = new ObjectIdentifier(new int[]{2, 5, 4, 7}, "L", RFC1779_NAMES);
    /* renamed from: O */
    private static final ObjectIdentifier f18O = new ObjectIdentifier(new int[]{2, 5, 4, 10}, "O", RFC1779_NAMES);
    private static final ObjectIdentifier OU = new ObjectIdentifier(new int[]{2, 5, 4, 11}, "OU", RFC1779_NAMES);
    private static final HashMap RFC1779_NAMES = new HashMap(10);
    private static final HashMap RFC2253_NAMES = new HashMap(10);
    private static final HashMap RFC2459_NAMES = new HashMap(10);
    private static final ObjectIdentifier SERIALNUMBER = new ObjectIdentifier(new int[]{2, 5, 4, 5}, "SERIALNUMBER", RFC2459_NAMES);
    private static final int SIZE = 10;
    private static final ObjectIdentifier ST = new ObjectIdentifier(new int[]{2, 5, 4, 8}, "ST", RFC1779_NAMES);
    private static final ObjectIdentifier STREET = new ObjectIdentifier(new int[]{2, 5, 4, 9}, "STREET", RFC1779_NAMES);
    private static final ObjectIdentifier SURNAME = new ObjectIdentifier(new int[]{2, 5, 4, 4}, "SURNAME", RFC2459_NAMES);
    /* renamed from: T */
    private static final ObjectIdentifier f19T = new ObjectIdentifier(new int[]{2, 5, 4, 12}, "T", RFC2459_NAMES);
    private static final ObjectIdentifier UID = new ObjectIdentifier(new int[]{0, 9, 2342, 19200300, 100, 1, 1}, "UID", RFC2253_NAMES);
    public static final ASN1Type attributeValue = new ASN1Type(19) {
        public boolean checkTag(int tag) {
            return true;
        }

        public Object decode(BerInputStream in) throws IOException {
            String str = null;
            if (DirectoryString.ASN1.checkTag(in.tag)) {
                str = (String) DirectoryString.ASN1.decode(in);
            } else {
                in.readContent();
            }
            byte[] bytesEncoded = new byte[(in.getOffset() - in.getTagOffset())];
            System.arraycopy(in.getBuffer(), in.getTagOffset(), bytesEncoded, 0, bytesEncoded.length);
            return new AttributeValue(str, bytesEncoded, in.tag);
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            throw new RuntimeException(Messages.getString("security.179"));
        }

        public void encodeASN(BerOutputStream out) {
            AttributeValue av = out.content;
            if (av.encoded != null) {
                out.content = av.encoded;
                out.encodeANY();
                return;
            }
            out.encodeTag(av.getTag());
            out.content = av.bytes;
            out.encodeString();
        }

        public void setEncodingContent(BerOutputStream out) {
            AttributeValue av = out.content;
            if (av.encoded != null) {
                out.length = av.encoded.length;
            } else if (av.getTag() == 12) {
                out.content = av.rawString;
                ASN1StringType.UTF8STRING.setEncodingContent(out);
                av.bytes = (byte[]) out.content;
                out.content = av;
            } else {
                try {
                    av.bytes = av.rawString.getBytes("UTF-8");
                    out.length = av.bytes.length;
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e.getMessage());
                }
            }
        }

        public void encodeContent(BerOutputStream out) {
            throw new RuntimeException(Messages.getString("security.17A"));
        }

        public int getEncodedLength(BerOutputStream out) {
            if (out.content.encoded != null) {
                return out.length;
            }
            return super.getEncodedLength(out);
        }
    };
    private final ObjectIdentifier oid;
    private AttributeValue value;

    static {
        RFC1779_NAMES.put(CN.getName(), CN);
        RFC1779_NAMES.put(f17L.getName(), f17L);
        RFC1779_NAMES.put(ST.getName(), ST);
        RFC1779_NAMES.put(f18O.getName(), f18O);
        RFC1779_NAMES.put(OU.getName(), OU);
        RFC1779_NAMES.put(f16C.getName(), f16C);
        RFC1779_NAMES.put(STREET.getName(), STREET);
        RFC2253_NAMES.putAll(RFC1779_NAMES);
        RFC2253_NAMES.put(DC.getName(), DC);
        RFC2253_NAMES.put(UID.getName(), UID);
        RFC2459_NAMES.put(DNQ.getName(), DNQ);
        RFC2459_NAMES.put(DNQUALIFIER.getName(), DNQUALIFIER);
        RFC2459_NAMES.put(EMAILADDRESS.getName(), EMAILADDRESS);
        RFC2459_NAMES.put(GENERATION.getName(), GENERATION);
        RFC2459_NAMES.put(GIVENNAME.getName(), GIVENNAME);
        RFC2459_NAMES.put(INITIALS.getName(), INITIALS);
        RFC2459_NAMES.put(SERIALNUMBER.getName(), SERIALNUMBER);
        RFC2459_NAMES.put(SURNAME.getName(), SURNAME);
        RFC2459_NAMES.put(f19T.getName(), f19T);
        for (ObjectIdentifier addOID : RFC2253_NAMES.values()) {
            addOID(addOID);
        }
        for (ObjectIdentifier o : RFC2459_NAMES.values()) {
            if (o != DNQUALIFIER) {
                addOID(o);
            }
        }
        KNOWN_NAMES.putAll(RFC2253_NAMES);
        KNOWN_NAMES.putAll(RFC2459_NAMES);
    }

    private AttributeTypeAndValue(int[] oid, AttributeValue value) throws IOException {
        ObjectIdentifier thisOid = getOID(oid);
        if (thisOid == null) {
            thisOid = new ObjectIdentifier(oid);
        }
        this.oid = thisOid;
        this.value = value;
    }

    public AttributeTypeAndValue(String sOid, AttributeValue value) throws IOException {
        if (sOid.charAt(0) < '0' || sOid.charAt(0) > '9') {
            this.oid = (ObjectIdentifier) KNOWN_NAMES.get(Util.toUpperCase(sOid));
            if (this.oid == null) {
                throw new IOException(Messages.getString("security.178", (Object) sOid));
            }
        }
        int[] array = custom.org.apache.harmony.security.asn1.ObjectIdentifier.toIntArray(sOid);
        ObjectIdentifier thisOid = getOID(array);
        if (thisOid == null) {
            thisOid = new ObjectIdentifier(array);
        }
        this.oid = thisOid;
        this.value = value;
    }

    public void appendName(String attrFormat, StringBuffer buf) {
        boolean hexFormat = false;
        if ("RFC1779".equals(attrFormat)) {
            if (RFC1779_NAMES == this.oid.getGroup()) {
                buf.append(this.oid.getName());
            } else {
                buf.append(this.oid.toOIDString());
            }
            buf.append('=');
            if (this.value.escapedString == this.value.getHexString()) {
                buf.append(Util.toUpperCase(this.value.getHexString()));
                return;
            } else if (this.value.escapedString.length() != this.value.rawString.length()) {
                this.value.appendQEString(buf);
                return;
            } else {
                buf.append(this.value.escapedString);
                return;
            }
        }
        HashMap group = this.oid.getGroup();
        if (RFC1779_NAMES == group || RFC2253_NAMES == group) {
            buf.append(this.oid.getName());
            if ("CANONICAL".equals(attrFormat)) {
                int tag = this.value.getTag();
                if (!(ASN1StringType.UTF8STRING.checkTag(tag) || ASN1StringType.PRINTABLESTRING.checkTag(tag))) {
                    hexFormat = true;
                }
            }
        } else {
            buf.append(this.oid.toString());
            hexFormat = true;
        }
        buf.append('=');
        if (hexFormat) {
            buf.append(this.value.getHexString());
        } else if ("CANONICAL".equals(attrFormat)) {
            buf.append(this.value.makeCanonical());
        } else {
            buf.append(this.value.escapedString);
        }
    }

    public ObjectIdentifier getType() {
        return this.oid;
    }

    private static ObjectIdentifier getOID(int[] oid) {
        ObjectIdentifier[] list = KNOWN_OIDS[hashIntArray(oid) % CAPACITY];
        for (int i = 0; list[i] != null; i++) {
            if (Arrays.equals(oid, list[i].getOid())) {
                return list[i];
            }
        }
        return null;
    }

    private static void addOID(ObjectIdentifier oid) {
        int[] newOid = oid.getOid();
        ObjectIdentifier[] list = KNOWN_OIDS[hashIntArray(newOid) % CAPACITY];
        int i = 0;
        while (list[i] != null) {
            if (Arrays.equals(newOid, list[i].getOid())) {
                throw new Error(Messages.getString("security.17B", oid.getName(), list[i].getName()));
            }
            i++;
        }
        if (i == CAPACITY - 1) {
            throw new Error(Messages.getString("security.17C"));
        }
        list[i] = oid;
    }

    private static int hashIntArray(int[] oid) {
        int intHash = 0;
        int i = 0;
        while (i < oid.length && i < 4) {
            intHash += oid[i] << (i * 8);
            i++;
        }
        return Integer.MAX_VALUE & intHash;
    }
}
