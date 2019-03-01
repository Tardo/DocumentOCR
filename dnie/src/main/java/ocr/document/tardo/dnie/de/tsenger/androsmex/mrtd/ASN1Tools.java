package de.tsenger.androsmex.mrtd;

import org.bouncycastle.asn1.eac.CertificateBody;

public class ASN1Tools {
    private static int asn1DataLength(byte[] asn1Data, int startByte) {
        if (JSmexTools.toUnsignedInt(asn1Data[startByte + 1]) <= CertificateBody.profileType) {
            return JSmexTools.toUnsignedInt(asn1Data[startByte + 1]);
        }
        if (JSmexTools.toUnsignedInt(asn1Data[startByte + 1]) == 129) {
            return JSmexTools.toUnsignedInt(asn1Data[startByte + 2]);
        }
        if (JSmexTools.toUnsignedInt(asn1Data[startByte + 1]) == 130) {
            return (JSmexTools.toUnsignedInt(asn1Data[startByte + 2]) * 256) + JSmexTools.toUnsignedInt(asn1Data[startByte + 3]);
        }
        return 0;
    }

    public static byte[] extractTag(byte tag, byte[] data, int startByte) {
        for (int i = startByte; i < data.length; i++) {
            if (data[i] == tag) {
                int len = asn1DataLength((byte[]) data.clone(), i);
                int addlen = 2;
                if (data[i + 1] == (byte) -127) {
                    addlen = 3;
                } else if (data[i + 1] == (byte) -126) {
                    addlen = 4;
                }
                byte[] dataObject = new byte[(len + addlen)];
                System.arraycopy(data, i, dataObject, 0, dataObject.length);
                return dataObject;
            }
        }
        return null;
    }

    public static byte[] extractTLV(short tag, byte[] data, int startByte) {
        for (int i = startByte; i < data.length - 1; i++) {
            if ((JSmexTools.toUnsignedInt(data[i]) * 256) + JSmexTools.toUnsignedInt(data[i + 1]) == tag) {
                int len = asn1DataLength((byte[]) data.clone(), i + 1);
                int addlen = 3;
                if (data[i + 2] == (byte) -127) {
                    addlen = 4;
                } else if (data[i + 2] == (byte) -126) {
                    addlen = 5;
                }
                byte[] dataObject = new byte[(len + addlen)];
                System.arraycopy(data, i, dataObject, 0, dataObject.length);
                return dataObject;
            }
        }
        return null;
    }
}
