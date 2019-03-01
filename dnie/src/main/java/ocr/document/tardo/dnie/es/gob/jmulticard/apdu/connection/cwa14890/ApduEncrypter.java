package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.bertlv.BerTlv;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

final class ApduEncrypter {
    private static final byte CLA_OF_PROTECTED_APDU = (byte) 12;
    private static final byte ISO7816_PADDING_PREFIX = Byte.MIN_VALUE;
    private static final byte TAG_DATA_TLV = (byte) -121;
    private static final byte TAG_LE_TLV = (byte) -105;
    private static final byte TAG_MAC_TLV = (byte) -114;
    private static final byte TAG_SW_TLV = (byte) -103;
    private static final byte TLV_VALUE_PREFIX_TO_MAC = (byte) 1;

    private ApduEncrypter() {
    }

    static CipheredApdu protectAPDU(CommandApdu unprotectedAPDU, byte[] keyCipher, byte[] keyMac, byte[] sendSequenceCounter, CryptoHelper cryptoHelper) throws IOException {
        byte cla = unprotectedAPDU.getCla();
        byte ins = unprotectedAPDU.getIns();
        byte p1 = unprotectedAPDU.getP1();
        byte p2 = unprotectedAPDU.getP2();
        byte[] data = unprotectedAPDU.getData();
        Integer le = unprotectedAPDU.getLe();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Object tlvDataBytes = new byte[0];
        if (data != null && data.length > 0) {
            int i;
            baos.write(1);
            byte[] paddedData = addPadding7816(data);
            baos.write(cryptoHelper.desedeEncrypt(paddedData, keyCipher));
            for (i = 0; i < paddedData.length; i++) {
                paddedData[i] = (byte) 0;
            }
            for (i = 0; i < data.length; i++) {
                data[i] = (byte) 0;
            }
            tlvDataBytes = new Tlv(TAG_DATA_TLV, baos.toByteArray()).getBytes();
        }
        Object tlvLeBytes = new byte[0];
        if (le != null) {
            tlvLeBytes = new Tlv(TAG_LE_TLV, new byte[]{le.byteValue()}).getBytes();
        }
        byte[] completeDataBytes = new byte[(tlvDataBytes.length + tlvLeBytes.length)];
        System.arraycopy(tlvDataBytes, 0, completeDataBytes, 0, tlvDataBytes.length);
        System.arraycopy(tlvLeBytes, 0, completeDataBytes, tlvDataBytes.length, tlvLeBytes.length);
        cla = (byte) (cla | 12);
        baos.reset();
        baos.write(addPadding7816(new byte[]{cla, ins, p1, p2}));
        baos.write(completeDataBytes);
        return new CipheredApdu(cla, ins, p1, p2, completeDataBytes, generateMac(addPadding7816(baos.toByteArray()), sendSequenceCounter, keyMac, cryptoHelper));
    }

    private static byte[] addPadding7816(byte[] data) {
        byte[] paddedData = new byte[(((data.length / 8) + 1) * 8)];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        paddedData[data.length] = ISO7816_PADDING_PREFIX;
        for (int i = data.length + 1; i < paddedData.length; i++) {
            paddedData[i] = (byte) 0;
        }
        return paddedData;
    }

    private static byte[] removePadding7816(byte[] paddedData) {
        int i = paddedData.length - 1;
        while (i >= 0) {
            if (paddedData[i] == ISO7816_PADDING_PREFIX) {
                if (i == 0) {
                    return new byte[0];
                }
                return HexUtils.subArray(paddedData, 0, i);
            } else if (paddedData[i] != (byte) 0) {
                return paddedData;
            } else {
                i--;
            }
        }
        return paddedData;
    }

    private static byte[] generateMac(byte[] dataPadded, byte[] ssc, byte[] kMac, CryptoHelper cryptoHelper) throws IOException {
        byte[] keyDesBytes = new byte[8];
        System.arraycopy(kMac, 0, keyDesBytes, 0, 8);
        byte[] tmpData = cryptoHelper.desEncrypt(ssc, keyDesBytes);
        int i = 0;
        while (i < dataPadded.length - 8) {
            tmpData = cryptoHelper.desEncrypt(HexUtils.xor(tmpData, HexUtils.subArray(dataPadded, i, 8)), keyDesBytes);
            i += 8;
        }
        byte[] keyTdesBytes = new byte[24];
        System.arraycopy(kMac, 0, keyTdesBytes, 0, 16);
        System.arraycopy(kMac, 0, keyTdesBytes, 16, 8);
        return HexUtils.subArray(cryptoHelper.desedeEncrypt(HexUtils.xor(tmpData, HexUtils.subArray(dataPadded, i, 8)), keyTdesBytes), 0, 8);
    }

    static ResponseApdu decryptResponseApdu(ResponseApdu responseApdu, byte[] keyCipher, byte[] ssc, byte[] kMac, CryptoHelper cryptoHelper) throws IOException {
        if (!responseApdu.isOk()) {
            return new ResponseApdu(responseApdu.getStatusWord().getBytes());
        }
        ByteArrayInputStream recordOfTlvs = new ByteArrayInputStream(responseApdu.getData());
        BerTlv dataTlv = null;
        BerTlv swTlv = null;
        BerTlv macTlv = null;
        try {
            BerTlv tlv = BerTlv.getInstance(recordOfTlvs);
            if (tlv.getTag().getTagValue() == -121) {
                dataTlv = tlv;
                tlv = BerTlv.getInstance(recordOfTlvs);
            }
            if (tlv.getTag().getTagValue() == -103) {
                swTlv = tlv;
                tlv = BerTlv.getInstance(recordOfTlvs);
            }
            if (tlv.getTag().getTagValue() == -114) {
                macTlv = tlv;
            }
            if (macTlv == null) {
                throw new SecureChannelException("No se ha encontrado el TLV del MAC en la APDU");
            } else if (swTlv == null) {
                throw new SecureChannelException("No se ha encontrado el TLV del StatusWord en la APDU cifrada");
            } else {
                verifyMac(HexUtils.subArray(responseApdu.getData(), 0, (dataTlv != null ? ((dataTlv.getValue().length / 128) + 2) + dataTlv.getValue().length : 0) + (swTlv.getValue().length + 2)), macTlv.getValue(), ssc, kMac, cryptoHelper);
                if (dataTlv == null) {
                    return new ResponseApdu(swTlv.getValue());
                }
                byte[] decryptedData = removePadding7816(cryptoHelper.desedeDecrypt(HexUtils.subArray(dataTlv.getValue(), 1, dataTlv.getValue().length - 1), keyCipher));
                byte[] responseApduBytes = new byte[(decryptedData.length + swTlv.getValue().length)];
                System.arraycopy(decryptedData, 0, responseApduBytes, 0, decryptedData.length);
                System.arraycopy(swTlv.getValue(), 0, responseApduBytes, decryptedData.length, swTlv.getValue().length);
                return new ResponseApdu(responseApduBytes);
            }
        } catch (NegativeArraySizeException e) {
            throw new ApduConnectionException("Error en el formato de la respuesta remitida por el canal seguro", e);
        }
    }

    private static void verifyMac(byte[] verificableData, byte[] macTlvBytes, byte[] ssc, byte[] kMac, CryptoHelper cryptoHelper) {
        try {
            if (!HexUtils.arrayEquals(macTlvBytes, generateMac(addPadding7816(verificableData), ssc, kMac, cryptoHelper))) {
                throw new InvalidCryptographicChecksum();
            }
        } catch (IOException e) {
            throw new SecurityException("No se pudo calcular el MAC teorico de la respuesta del DNIe para su verificacion");
        }
    }
}
