package es.gob.jmulticard.card.iso7816eight;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.apdu.iso7816eight.PsoVerifyCertificateApduCommand;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.jse.smartcardio.SmartCardNFCConnection;

public abstract class Iso7816EightCard extends Iso7816FourCard {
    public Iso7816EightCard(byte c, ApduConnection conn) throws ApduConnectionException {
        super(c, conn);
    }

    public Iso7816EightCard(byte c, SmartCardNFCConnection conn) throws ApduConnectionException {
        super(c, conn);
    }

    public void verifyCertificate(byte[] cert) throws ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new PsoVerifyCertificateApduCommand((byte) 0, cert));
        if (!res.isOk()) {
            throw new SecureChannelException("Error en la verificacion del certificado. Se obtuvo el error: " + HexUtils.hexify(res.getBytes(), true));
        }
    }
}
