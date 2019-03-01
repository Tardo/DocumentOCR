package de.tsenger.androsmex;

import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import java.io.IOException;

public interface CardHandler {
    int getMaxTranceiveLength();

    boolean isConnected();

    ResponseAPDU transceive(CommandAPDU commandAPDU) throws IOException, SecureMessagingException;
}
