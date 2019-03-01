package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Cwa14890OneConnection implements ApduConnection {
    private static final StatusWord INVALID_CIPHERED_DATA = new StatusWord((byte) 105, (byte) -120);
    private static final StatusWord INVALID_CRYPTO_CHECKSUM = new StatusWord((byte) 102, (byte) -120);
    private static final byte MSB_INCORRECT_LE = (byte) 108;
    private static final byte[] SECURE_CHANNEL_KENC_AUX = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 1};
    private static final byte[] SECURE_CHANNEL_KMAC_AUX = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 2};
    private static final String SHA1_ALGORITHM_NAME = "SHA1";
    private final Cwa14890Card card;
    private final CryptoHelper cryptoHelper;
    private byte[] kenc = null;
    private byte[] kmac = null;
    private boolean openState = false;
    private byte[] ssc = null;
    private final ApduConnection subConnection;

    public Cwa14890OneConnection(Cwa14890Card card, ApduConnection connection, CryptoHelper cryptoHelper) {
        if (card == null) {
            throw new IllegalArgumentException("No se ha proporcionado la tarjeta CWA-14890 con la que abrir el canal seguro");
        } else if (cryptoHelper == null) {
            throw new IllegalArgumentException("CryptoHelper no puede ser nulo");
        } else {
            this.card = card;
            if (connection instanceof Cwa14890OneConnection) {
                this.subConnection = ((Cwa14890OneConnection) connection).getSubConnection();
            } else {
                this.subConnection = connection;
            }
            this.cryptoHelper = cryptoHelper;
        }
    }

    public void open() throws ApduConnectionException {
        ApduConnection conn = this.subConnection;
        if (!(conn instanceof Cwa14890OneConnection)) {
            if (conn.isOpen()) {
                conn.reset();
            } else {
                conn.open();
            }
        }
        byte[] serial = getPaddedSerial();
        try {
            this.card.verifyCaIntermediateIcc();
            this.card.verifyIcc();
            try {
                RSAPublicKey iccPublicKey = (RSAPublicKey) this.cryptoHelper.generateCertificate(this.card.getIccCertEncoded()).getPublicKey();
                try {
                    this.card.verifyIfdCertificateChain();
                    try {
                        byte[] randomIfd = this.cryptoHelper.generateRandomBytes(8);
                        try {
                            byte[] kicc = internalAuthentication(randomIfd, iccPublicKey);
                            byte[] randomIcc = this.card.getChallenge();
                            try {
                                byte[] kidficc = HexUtils.xor(kicc, externalAuthentication(serial, randomIcc, iccPublicKey));
                                try {
                                    this.kenc = generateKenc(kidficc);
                                    try {
                                        this.kmac = generateKmac(kidficc);
                                        this.ssc = generateSsc(randomIfd, randomIcc);
                                        this.openState = true;
                                    } catch (IOException e) {
                                        conn.close();
                                        throw new ApduConnectionException("Error al generar la clave KMac para el tratamiento del canal seguro", e);
                                    }
                                } catch (IOException e2) {
                                    conn.close();
                                    throw new ApduConnectionException("Error al generar la clave KEnc para el tratamiento del canal seguro", e2);
                                }
                            } catch (Exception e3) {
                                conn.close();
                                throw new ApduConnectionException("Error durante el proceso de autenticacion externa de la tarjeta", e3);
                            }
                        } catch (Exception e32) {
                            conn.close();
                            throw new ApduConnectionException("Error durante el proceso de autenticacion interna de la tarjeta", e32);
                        }
                    } catch (IOException e1) {
                        conn.close();
                        throw new SecureChannelException("No se pudo generar el array de aleatorios", e1);
                    }
                } catch (Exception e322) {
                    conn.close();
                    throw new ApduConnectionException("Error al verificar la cadena de certificados del controlador", e322);
                }
            } catch (CertificateException e4) {
                conn.close();
                throw new ApduConnectionException("No se pudo obtener la clave publica del certificado de componente", e4);
            } catch (Exception e3222) {
                conn.close();
                throw new ApduConnectionException("No se pudo leer certificado de componente", e3222);
            }
        } catch (SecurityException e5) {
            conn.close();
            throw new IllegalStateException("Condicion de seguridad no satisfecha en la validacion de los certificados CWA-14890: " + e5.getMessage());
        } catch (CertificateException e42) {
            conn.close();
            throw new IllegalStateException("No se han podido tratar los certificados CWA-14890: " + e42.getMessage());
        } catch (IOException e22) {
            conn.close();
            throw new IllegalStateException("No se han podido validar los certificados CWA-14890: " + e22.getMessage());
        }
    }

    private byte[] generateKenc(byte[] kidficc) throws IOException {
        byte[] kidficcConcat = new byte[(kidficc.length + SECURE_CHANNEL_KENC_AUX.length)];
        System.arraycopy(kidficc, 0, kidficcConcat, 0, kidficc.length);
        System.arraycopy(SECURE_CHANNEL_KENC_AUX, 0, kidficcConcat, kidficc.length, SECURE_CHANNEL_KENC_AUX.length);
        byte[] keyEnc = new byte[16];
        System.arraycopy(this.cryptoHelper.digest(SHA1_ALGORITHM_NAME, kidficcConcat), 0, keyEnc, 0, keyEnc.length);
        return keyEnc;
    }

    private byte[] generateKmac(byte[] kidficc) throws IOException {
        byte[] kidficcConcat = new byte[(kidficc.length + SECURE_CHANNEL_KMAC_AUX.length)];
        System.arraycopy(kidficc, 0, kidficcConcat, 0, kidficc.length);
        System.arraycopy(SECURE_CHANNEL_KMAC_AUX, 0, kidficcConcat, kidficc.length, SECURE_CHANNEL_KMAC_AUX.length);
        byte[] keyMac = new byte[16];
        System.arraycopy(this.cryptoHelper.digest(SHA1_ALGORITHM_NAME, kidficcConcat), 0, keyMac, 0, keyMac.length);
        return keyMac;
    }

    private static byte[] generateSsc(byte[] randomIfd, byte[] randomIcc) {
        byte[] ssc = new byte[8];
        System.arraycopy(randomIcc, 4, ssc, 0, 4);
        System.arraycopy(randomIfd, 4, ssc, 4, 4);
        return ssc;
    }

    public byte[] internalAuthentication(byte[] randomIfd, RSAPublicKey iccPublicKey) throws SecureChannelException, ApduConnectionException, IOException {
        try {
            this.card.setKeysToAuthentication(this.card.getChrCCvIfd(), this.card.getRefIccPrivateKey());
            byte[] sigMin = this.cryptoHelper.rsaDecrypt(this.card.getInternalAuthenticateMessage(randomIfd, this.card.getChrCCvIfd()), this.card.getIfdPrivateKey());
            byte[] desMsg = this.cryptoHelper.rsaEncrypt(sigMin, iccPublicKey);
            if (!(desMsg[0] == (byte) 106 && desMsg[desMsg.length - 1] == (byte) -68)) {
                byte[] sub = iccPublicKey.getModulus().subtract(new BigInteger(sigMin)).toByteArray();
                byte[] niccMinusSig = new byte[128];
                if (sub.length <= 128 || sub[0] != (byte) 0) {
                    System.arraycopy(sub, 0, niccMinusSig, 0, sub.length);
                } else {
                    System.arraycopy(sub, 1, niccMinusSig, 0, sub.length - 1);
                }
                desMsg = this.cryptoHelper.rsaEncrypt(niccMinusSig, iccPublicKey);
                if (!(desMsg[0] == (byte) 106 && desMsg[desMsg.length - 1] == (byte) -68)) {
                    throw new SecureChannelException("Error en la autenticacion interna para el establecimiento del canal seguro. El mensaje descifrado es: " + HexUtils.hexify(desMsg, true));
                }
            }
            byte[] prnd1 = new byte[74];
            System.arraycopy(desMsg, 1, prnd1, 0, prnd1.length);
            byte[] kicc = new byte[32];
            System.arraycopy(desMsg, 75, kicc, 0, kicc.length);
            byte[] hash = new byte[20];
            System.arraycopy(desMsg, 107, hash, 0, hash.length);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(prnd1);
            baos.write(kicc);
            baos.write(randomIfd);
            baos.write(this.card.getChrCCvIfd());
            byte[] calculatedHash = this.cryptoHelper.digest(SHA1_ALGORITHM_NAME, baos.toByteArray());
            if (HexUtils.arrayEquals(hash, calculatedHash)) {
                return kicc;
            }
            throw new SecureChannelException("Error en la comprobacion de la clave de autenticacion interna. Se obtuvo el hash '" + HexUtils.hexify(calculatedHash, false) + "' cuando se esperaba:" + HexUtils.hexify(hash, false));
        } catch (Exception e) {
            throw new SecureChannelException("Error durante el establecimiento de la clave publica de Terminal y la privada de componente para su atenticacion", e);
        }
    }

    private byte[] externalAuthentication(byte[] serial, byte[] randomIcc, RSAPublicKey iccPublicKey) throws IOException {
        byte[] prnd2 = this.cryptoHelper.generateRandomBytes(74);
        byte[] kifd = this.cryptoHelper.generateRandomBytes(32);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(prnd2);
        baos.write(kifd);
        baos.write(randomIcc);
        baos.write(serial);
        byte[] hash = this.cryptoHelper.digest(SHA1_ALGORITHM_NAME, baos.toByteArray());
        baos.reset();
        baos.write(106);
        baos.write(prnd2);
        baos.write(kifd);
        baos.write(hash);
        baos.write(-68);
        byte[] msg = baos.toByteArray();
        RSAPrivateKey ifdPrivateKey = this.card.getIfdPrivateKey();
        BigInteger biSig = new BigInteger(1, this.cryptoHelper.rsaDecrypt(msg, ifdPrivateKey));
        if (this.card.externalAuthentication(this.cryptoHelper.rsaEncrypt(ifdPrivateKey.getModulus().subtract(biSig).min(biSig).toByteArray(), iccPublicKey))) {
            return kifd;
        }
        throw new SecureChannelException("Error durante la autenticacion externa del canal seguro");
    }

    private byte[] getPaddedSerial() throws ApduConnectionException {
        byte[] serial = this.card.getSerialNumber();
        byte[] paddedSerial = serial;
        if (paddedSerial.length < 8) {
            paddedSerial = new byte[8];
            int i = 0;
            while (i < 8 - serial.length) {
                paddedSerial[i] = (byte) 0;
                i++;
            }
            System.arraycopy(serial, 0, paddedSerial, i, serial.length);
        }
        return paddedSerial;
    }

    public void close() throws ApduConnectionException {
        if (this.openState) {
            this.subConnection.close();
            this.openState = false;
        }
    }

    public ResponseApdu transmit(CommandApdu command) throws ApduConnectionException {
        try {
            this.ssc = increment(this.ssc);
            ResponseApdu responseApdu = this.subConnection.transmit(ApduEncrypter.protectAPDU(command, this.kenc, this.kmac, this.ssc, this.cryptoHelper));
            if (INVALID_CRYPTO_CHECKSUM.equals(responseApdu.getStatusWord())) {
                throw new InvalidCryptographicChecksum();
            } else if (INVALID_CIPHERED_DATA.equals(responseApdu.getStatusWord())) {
                throw new InvalidCipheredData();
            } else if (responseApdu.isOk()) {
                try {
                    this.ssc = increment(this.ssc);
                    ResponseApdu decipherApdu = ApduEncrypter.decryptResponseApdu(responseApdu, this.kenc, this.ssc, this.kmac, this.cryptoHelper);
                    if (decipherApdu.getStatusWord().getMsb() == MSB_INCORRECT_LE) {
                        command.setLe(decipherApdu.getStatusWord().getLsb());
                        decipherApdu = transmit(command);
                    }
                    return decipherApdu;
                } catch (Exception e) {
                    throw new ApduConnectionException("Error en la desencriptacion de la APDU de respuesta recibida por el canal seguro", e);
                }
            } else {
                throw new SecureChannelException("Error en la APDU de respuesta cifrada con el codigo " + responseApdu.getStatusWord());
            }
        } catch (IOException e2) {
            throw new SecureChannelException("Error en la encriptacion de la APDU para su envio por el canal seguro", e2);
        }
    }

    public byte[] reset() throws ApduConnectionException {
        this.openState = false;
        byte[] atr = this.subConnection.reset();
        open();
        return atr;
    }

    public void addCardConnectionListener(CardConnectionListener ccl) {
        this.subConnection.addCardConnectionListener(ccl);
    }

    public void removeCardConnectionListener(CardConnectionListener ccl) {
        this.subConnection.removeCardConnectionListener(ccl);
    }

    public long[] getTerminals(boolean onlyWithCardPresent) throws ApduConnectionException {
        return this.subConnection.getTerminals(onlyWithCardPresent);
    }

    public String getTerminalInfo(int terminal) throws ApduConnectionException {
        return this.subConnection.getTerminalInfo(terminal);
    }

    public void setTerminal(int t) {
        this.subConnection.setTerminal(t);
    }

    public boolean isOpen() {
        return this.openState && this.subConnection.isOpen();
    }

    private static byte[] increment(byte[] data) {
        byte[] biArray = new BigInteger(1, data).add(BigInteger.ONE).toByteArray();
        byte[] incrementedValue;
        if (biArray.length > 8) {
            incrementedValue = new byte[8];
            System.arraycopy(biArray, biArray.length - incrementedValue.length, incrementedValue, 0, incrementedValue.length);
            return incrementedValue;
        } else if (biArray.length >= 8) {
            return biArray;
        } else {
            incrementedValue = new byte[8];
            System.arraycopy(biArray, 0, incrementedValue, incrementedValue.length - biArray.length, biArray.length);
            return incrementedValue;
        }
    }

    public ApduConnection getSubConnection() {
        return this.subConnection;
    }
}
