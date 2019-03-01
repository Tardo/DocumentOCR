package es.gob.jmulticard.apdu.iso7816eight;

import es.gob.jmulticard.apdu.CommandApdu;

public final class PsoVerifyCertificateApduCommand extends CommandApdu {
    private static final byte DATA_FIELD_COMMAND_VERIFY_CERTIFICATE = (byte) -82;
    private static final byte DATA_FIELD_RESPONSE_EMPTY = (byte) 0;
    private static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 42;

    public PsoVerifyCertificateApduCommand(byte cla, byte[] certEncoding) {
        super(cla, INS_PERFORM_SECURITY_OPERATION, (byte) 0, DATA_FIELD_COMMAND_VERIFY_CERTIFICATE, certEncoding, null);
    }
}
