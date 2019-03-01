package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.HexUtils;
import java.util.Properties;

final class OidDictionary {
    private static Properties dic = new Properties();

    private OidDictionary() {
    }

    static {
        dic.put("55-04-06", "C");
        dic.put("55-04-05", "SERIALNUMBER");
        dic.put("55-04-04", "SURNAME");
        dic.put("55-04-2A", "GIVENNAME");
        dic.put("55-04-03", "CN");
        dic.put("55-04-0A", "O");
        dic.put("55-04-0B", "OU");
        dic.put("55-04-07", "L");
        dic.put("55-04-08", "ST");
    }

    static String getOidDescription(byte[] rawOid) {
        if (rawOid == null) {
            throw new IllegalArgumentException("No hay descripcion para un OID nulo");
        }
        String key = HexUtils.hexify(rawOid, true);
        return dic.getProperty(key) != null ? dic.getProperty(key) : key;
    }
}
