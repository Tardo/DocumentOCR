package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Choice;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1OctetString;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1StringType;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.x501.Name;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class GeneralName {
    public static final ASN1Choice ASN1 = new ASN1Choice(new ASN1Type[]{new ASN1Implicit(0, OtherName.ASN1), new ASN1Implicit(1, ASN1StringType.IA5STRING), new ASN1Implicit(2, ASN1StringType.IA5STRING), new ASN1Implicit(3, ORAddress.ASN1), new ASN1Implicit(4, Name.ASN1), new ASN1Implicit(5, EDIPartyName.ASN1), new ASN1Implicit(6, ASN1StringType.IA5STRING), new ASN1Implicit(7, ASN1OctetString.getInstance()), new ASN1Implicit(8, ASN1Oid.getInstance())}) {
        public Object getObjectToEncode(Object value) {
            return ((GeneralName) value).name;
        }

        public int getIndex(Object object) {
            return ((GeneralName) object).tag;
        }

        public Object getDecodedObject(BerInputStream in) throws IOException {
            GeneralName result;
            switch (in.choiceIndex) {
                case 0:
                    result = new GeneralName((OtherName) in.content);
                    break;
                case 1:
                case 2:
                    result = new GeneralName(in.choiceIndex, (String) in.content);
                    break;
                case 3:
                    result = new GeneralName((ORAddress) in.content);
                    break;
                case 4:
                    result = new GeneralName((Name) in.content);
                    break;
                case 5:
                    result = new GeneralName((EDIPartyName) in.content);
                    break;
                case 6:
                    String uri = in.content;
                    if (uri.indexOf(":") != -1) {
                        result = new GeneralName(in.choiceIndex, uri);
                        break;
                    }
                    throw new IOException(Messages.getString("security.190", (Object) uri));
                case 7:
                    result = new GeneralName((byte[]) in.content);
                    break;
                case 8:
                    result = new GeneralName(in.choiceIndex, ObjectIdentifier.toString((int[]) in.content));
                    break;
                default:
                    throw new IOException(Messages.getString("security.191", in.choiceIndex));
            }
            result.encoding = in.getEncoded();
            return result;
        }
    };
    public static final int DIR_NAME = 4;
    public static final int DNS_NAME = 2;
    public static final int EDIP_NAME = 5;
    public static final int IP_ADDR = 7;
    public static final int OTHER_NAME = 0;
    public static final int REG_ID = 8;
    public static final int RFC822_NAME = 1;
    public static final int UR_ID = 6;
    public static final int X400_ADDR = 3;
    private static ASN1Type[] nameASN1 = new ASN1Type[9];
    private byte[] encoding;
    private Object name;
    private byte[] name_encoding;
    private int tag;

    static {
        nameASN1[0] = OtherName.ASN1;
        nameASN1[1] = ASN1StringType.IA5STRING;
        nameASN1[2] = ASN1StringType.IA5STRING;
        nameASN1[6] = ASN1StringType.IA5STRING;
        nameASN1[3] = ORAddress.ASN1;
        nameASN1[4] = Name.ASN1;
        nameASN1[5] = EDIPartyName.ASN1;
        nameASN1[7] = ASN1OctetString.getInstance();
        nameASN1[8] = ASN1Oid.getInstance();
    }

    public GeneralName(int tag, String name) throws IOException {
        if (name == null) {
            throw new IOException(Messages.getString("security.28"));
        }
        this.tag = tag;
        switch (tag) {
            case 0:
            case 3:
            case 5:
                throw new IOException(Messages.getString("security.180", tag));
            case 1:
                this.name = name;
                return;
            case 2:
                checkDNS(name);
                this.name = name;
                return;
            case 4:
                this.name = new Name(name);
                return;
            case 6:
                checkURI(name);
                this.name = name;
                return;
            case 7:
                this.name = ipStrToBytes(name);
                return;
            case 8:
                this.name = oidStrToInts(name);
                return;
            default:
                throw new IOException(Messages.getString("security.181", tag));
        }
    }

    public GeneralName(OtherName name) {
        this.tag = 0;
        this.name = name;
    }

    public GeneralName(ORAddress name) {
        this.tag = 3;
        this.name = name;
    }

    public GeneralName(Name name) {
        this.tag = 4;
        this.name = name;
    }

    public GeneralName(EDIPartyName name) {
        this.tag = 5;
        this.name = name;
    }

    public GeneralName(byte[] name) throws IllegalArgumentException {
        int length = name.length;
        if (length == 4 || length == 8 || length == 16 || length == 32) {
            this.tag = 7;
            this.name = new byte[name.length];
            System.arraycopy(name, 0, this.name, 0, name.length);
            return;
        }
        throw new IllegalArgumentException(Messages.getString("security.182"));
    }

    public GeneralName(int tag, byte[] name) throws IOException {
        if (name == null) {
            throw new NullPointerException(Messages.getString("security.28"));
        } else if (tag < 0 || tag > 8) {
            throw new IOException(Messages.getString("security.183", tag));
        } else {
            this.tag = tag;
            this.name_encoding = new byte[name.length];
            System.arraycopy(name, 0, this.name_encoding, 0, name.length);
            this.name = nameASN1[tag].decode(this.name_encoding);
        }
    }

    public int getTag() {
        return this.tag;
    }

    public Object getName() {
        return this.name;
    }

    public boolean equals(Object _gname) {
        if (!(_gname instanceof GeneralName)) {
            return false;
        }
        GeneralName gname = (GeneralName) _gname;
        if (this.tag != gname.tag) {
            return false;
        }
        switch (this.tag) {
            case 0:
            case 3:
            case 4:
            case 5:
                return Arrays.equals(getEncoded(), gname.getEncoded());
            case 1:
            case 2:
            case 6:
                return ((String) this.name).equalsIgnoreCase((String) gname.getName());
            case 7:
                return Arrays.equals((byte[]) this.name, (byte[]) gname.name);
            case 8:
                return Arrays.equals((int[]) this.name, (int[]) gname.name);
            default:
                return false;
        }
    }

    public int hashCode() {
        switch (this.tag) {
            case 0:
            case 3:
            case 4:
            case 5:
                return getEncoded().hashCode();
            case 1:
            case 2:
            case 6:
            case 7:
            case 8:
                return this.name.hashCode();
            default:
                return super.hashCode();
        }
    }

    public boolean isAcceptable(GeneralName gname) {
        if (this.tag != gname.getTag()) {
            return false;
        }
        switch (this.tag) {
            case 0:
            case 3:
            case 4:
            case 5:
            case 8:
                return Arrays.equals(getEncoded(), gname.getEncoded());
            case 1:
                return ((String) gname.getName()).toLowerCase().endsWith(((String) this.name).toLowerCase());
            case 2:
                String dns = this.name;
                String _dns = (String) gname.getName();
                if (dns.equalsIgnoreCase(_dns)) {
                    return true;
                }
                return _dns.toLowerCase().endsWith("." + dns.toLowerCase());
            case 6:
                String uri = this.name;
                int begin = uri.indexOf("://") + 3;
                int end = uri.indexOf(47, begin);
                String host = end == -1 ? uri.substring(begin) : uri.substring(begin, end);
                uri = (String) gname.getName();
                begin = uri.indexOf("://") + 3;
                end = uri.indexOf(47, begin);
                String _host = end == -1 ? uri.substring(begin) : uri.substring(begin, end);
                if (host.startsWith(".")) {
                    return _host.toLowerCase().endsWith(host.toLowerCase());
                }
                return host.equalsIgnoreCase(_host);
            case 7:
                byte[] address = (byte[]) this.name;
                byte[] _address = (byte[]) gname.getName();
                int length = address.length;
                int _length = _address.length;
                if (length == _length) {
                    return Arrays.equals(address, _address);
                }
                if (length != _length * 2) {
                    return false;
                }
                int i = 0;
                while (i < _address.length) {
                    if (_address[i] < address[i] || _address[i] > address[i + _length]) {
                        return false;
                    }
                    i++;
                }
                return true;
            default:
                return true;
        }
    }

    public List getAsList() {
        ArrayList result = new ArrayList();
        result.add(new Integer(this.tag));
        switch (this.tag) {
            case 0:
                result.add(((OtherName) this.name).getEncoded());
                break;
            case 1:
            case 2:
            case 6:
                result.add(this.name);
                break;
            case 3:
                result.add(((ORAddress) this.name).getEncoded());
                break;
            case 4:
                result.add(((Name) this.name).getName("RFC2253"));
                break;
            case 5:
                result.add(((EDIPartyName) this.name).getEncoded());
                break;
            case 7:
                result.add(ipBytesToStr((byte[]) this.name));
                break;
            case 8:
                result.add(ObjectIdentifier.toString((int[]) this.name));
                break;
        }
        return Collections.unmodifiableList(result);
    }

    private String getBytesAsString(byte[] data) {
        String result = "";
        for (byte b : data) {
            String tail = Integer.toHexString(b & 255);
            if (tail.length() == 1) {
                tail = "0" + tail;
            }
            result = result + tail + " ";
        }
        return result;
    }

    public String toString() {
        String result = "";
        switch (this.tag) {
            case 0:
                return "otherName[0]: " + getBytesAsString(getEncoded());
            case 1:
                return "rfc822Name[1]: " + this.name;
            case 2:
                return "dNSName[2]: " + this.name;
            case 3:
                return "x400Address[3]: " + getBytesAsString(getEncoded());
            case 4:
                return "directoryName[4]: " + ((Name) this.name).getName("RFC2253");
            case 5:
                return "ediPartyName[5]: " + getBytesAsString(getEncoded());
            case 6:
                return "uniformResourceIdentifier[6]: " + this.name;
            case 7:
                return "iPAddress[7]: " + ipBytesToStr((byte[]) this.name);
            case 8:
                return "registeredID[8]: " + ObjectIdentifier.toString((int[]) this.name);
            default:
                return result;
        }
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public byte[] getEncodedName() {
        if (this.name_encoding == null) {
            this.name_encoding = nameASN1[this.tag].encode(this.name);
        }
        return this.name_encoding;
    }

    public static void checkDNS(String dns) throws IOException {
        byte[] bytes = dns.toLowerCase().getBytes("UTF-8");
        boolean first_letter = true;
        for (int i = 0; i < bytes.length; i++) {
            byte ch = bytes[i];
            if (first_letter) {
                if (bytes.length > 2 && ch == (byte) 42 && bytes[1] == (byte) 46) {
                    first_letter = false;
                } else if ((ch > (byte) 122 || ch < (byte) 97) && (ch < (byte) 48 || ch > (byte) 57)) {
                    throw new IOException(Messages.getString("security.184", Character.valueOf((char) ch), dns));
                } else {
                    first_letter = false;
                }
            } else if ((ch < (byte) 97 || ch > (byte) 122) && !((ch >= (byte) 48 && ch <= (byte) 57) || ch == (byte) 45 || ch == (byte) 46)) {
                throw new IOException(Messages.getString("security.185", (Object) dns));
            } else if (ch != (byte) 46) {
                continue;
            } else if (bytes[i - 1] == (byte) 45) {
                throw new IOException(Messages.getString("security.186", (Object) dns));
            } else {
                first_letter = true;
            }
        }
    }

    public static void checkURI(String uri) throws IOException {
        try {
            URI ur = new URI(uri);
            if (ur.getScheme() == null || ur.getRawSchemeSpecificPart().length() == 0) {
                throw new IOException(Messages.getString("security.187", (Object) uri));
            } else if (!ur.isAbsolute()) {
                throw new IOException(Messages.getString("security.188", (Object) uri));
            }
        } catch (URISyntaxException e) {
            throw ((IOException) new IOException(Messages.getString("security.189", (Object) uri)).initCause(e));
        }
    }

    public static int[] oidStrToInts(String oid) throws IOException {
        byte[] bytes = oid.getBytes("UTF-8");
        if (bytes[bytes.length - 1] == (byte) 46) {
            throw new IOException(Messages.getString("security.56", (Object) oid));
        }
        int[] result = new int[((bytes.length / 2) + 1)];
        int number = 0;
        int i = 0;
        while (i < bytes.length) {
            int value = 0;
            int pos = i;
            while (i < bytes.length && bytes[i] >= (byte) 48 && bytes[i] <= (byte) 57) {
                value = (value * 10) + (bytes[i] - 48);
                i++;
            }
            if (i == pos) {
                throw new IOException(Messages.getString("security.56", (Object) oid));
            }
            int number2 = number + 1;
            result[number] = value;
            if (i >= bytes.length) {
                number = number2;
                break;
            } else if (bytes[i] != (byte) 46) {
                throw new IOException(Messages.getString("security.56", (Object) oid));
            } else {
                i++;
                number = number2;
            }
        }
        if (number < 2) {
            throw new IOException(Messages.getString("security.18A", (Object) oid));
        }
        int[] res = new int[number];
        for (i = 0; i < number; i++) {
            res[i] = result[i];
        }
        return res;
    }

    public static byte[] ipStrToBytes(String ip) throws IOException {
        boolean isIPv4 = ip.indexOf(46) > 0;
        int num_components = isIPv4 ? 4 : 16;
        if (ip.indexOf(47) > 0) {
            num_components *= 2;
        }
        byte[] result = new byte[num_components];
        byte[] ip_bytes = ip.getBytes("UTF-8");
        int component = 0;
        boolean reading_second_bound = false;
        int i;
        int value;
        if (isIPv4) {
            i = 0;
            while (i < ip_bytes.length) {
                int digits = 0;
                value = 0;
                while (i < ip_bytes.length && ip_bytes[i] >= (byte) 48 && ip_bytes[i] <= (byte) 57) {
                    digits++;
                    if (digits > 3) {
                        throw new IOException(Messages.getString("security.18B", (Object) ip));
                    }
                    value = (value * 10) + (ip_bytes[i] - 48);
                    i++;
                }
                if (digits == 0) {
                    throw new IOException(Messages.getString("security.18C", (Object) ip));
                }
                result[component] = (byte) value;
                component++;
                if (i >= ip_bytes.length) {
                    break;
                } else if (ip_bytes[i] == (byte) 46 || ip_bytes[i] == (byte) 47) {
                    if (ip_bytes[i] == (byte) 47) {
                        if (reading_second_bound) {
                            throw new IOException(Messages.getString("security.18C", (Object) ip));
                        } else if (component != 4) {
                            throw new IOException(Messages.getString("security.18D", (Object) ip));
                        } else {
                            reading_second_bound = true;
                        }
                    }
                    if (component > (reading_second_bound ? 7 : 3)) {
                        throw new IOException(Messages.getString("security.18D", (Object) ip));
                    }
                    i++;
                } else {
                    throw new IOException(Messages.getString("security.18C", (Object) ip));
                }
            }
            if (component != num_components) {
                throw new IOException(Messages.getString("security.18D", (Object) ip));
            }
        } else if (ip_bytes.length == 39 || ip_bytes.length == 79) {
            boolean second_hex = false;
            boolean expect_delimiter = false;
            for (byte bytik : ip_bytes) {
                if (bytik >= (byte) 48 && bytik <= (byte) 57) {
                    value = bytik - 48;
                } else if (bytik >= (byte) 65 && bytik <= (byte) 70) {
                    value = bytik - 55;
                } else if (bytik >= (byte) 97 && bytik <= (byte) 102) {
                    value = bytik - 87;
                } else if (second_hex) {
                    throw new IOException(Messages.getString("security.18E", (Object) ip));
                } else if (bytik != (byte) 58 && bytik != (byte) 47) {
                    throw new IOException(Messages.getString("security.18E", (Object) ip));
                } else if (component % 2 == 1) {
                    throw new IOException(Messages.getString("security.18E", (Object) ip));
                } else {
                    if (bytik == (byte) 47) {
                        if (reading_second_bound) {
                            throw new IOException(Messages.getString("security.18E", (Object) ip));
                        } else if (component != 16) {
                            throw new IOException(Messages.getString("security.18F", (Object) ip));
                        } else {
                            reading_second_bound = true;
                        }
                    }
                    expect_delimiter = false;
                }
                if (expect_delimiter) {
                    throw new IOException(Messages.getString("security.18E", (Object) ip));
                }
                if (second_hex) {
                    result[component] = (byte) ((result[component] & 255) | value);
                    expect_delimiter = component % 2 == 1;
                    second_hex = false;
                    component++;
                } else {
                    result[component] = (byte) (value << 4);
                    second_hex = true;
                }
            }
            if (second_hex || component % 2 == 1) {
                throw new IOException(Messages.getString("security.18E", (Object) ip));
            }
        } else {
            throw new IOException(Messages.getString("security.18E", (Object) ip));
        }
        return result;
    }

    public static String ipBytesToStr(byte[] ip) {
        String result = "";
        int i;
        if (ip.length < 9) {
            i = 0;
            while (i < ip.length) {
                result = result + Integer.toString(ip[i] & 255);
                if (i != ip.length - 1) {
                    result = result + (i == 3 ? "/" : ".");
                }
                i++;
            }
        } else {
            i = 0;
            while (i < ip.length) {
                result = result + Integer.toHexString(ip[i] & 255);
                if (!(i % 2 == 0 || i == ip.length - 1)) {
                    result = result + (i == 15 ? "/" : ":");
                }
                i++;
            }
        }
        return result;
    }
}
