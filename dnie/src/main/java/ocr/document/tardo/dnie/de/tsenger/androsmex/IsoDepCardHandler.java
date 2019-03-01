package de.tsenger.androsmex;

import android.nfc.tech.IsoDep;
import android.util.Log;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.tools.HexString;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IsoDepCardHandler implements CardHandler {
    static final String TAG = "IsoDepCardHandler";
    private boolean generateLogDebug;
    private Logger logger;
    private SecureMessaging sm;
    private IsoDep tag;

    public IsoDepCardHandler(IsoDep tag) throws IOException {
        this.tag = null;
        this.sm = null;
        this.logger = null;
        this.generateLogDebug = false;
        this.logger = null;
        this.tag = tag;
        if (!tag.isConnected()) {
            connectTag();
        }
        this.tag.setTimeout(10000);
    }

    public IsoDepCardHandler(IsoDep tag, Logger logger) throws IOException {
        this.tag = null;
        this.sm = null;
        this.logger = null;
        this.generateLogDebug = false;
        this.logger = logger;
        this.tag = tag;
        if (!tag.isConnected()) {
            connectTag();
        }
        this.tag.setTimeout(10000);
    }

    private void connectTag() throws IOException {
        try {
            Log.d(TAG, "Connecting Tag!");
            this.tag.connect();
        } catch (Exception e) {
            Log.d(TAG, "Exception connecting Tag!");
        }
    }

    public byte[] getUID() {
        return this.tag.getTag().getId();
    }

    public byte[] getTagInfo() {
        if (this.tag.getHistoricalBytes() != null) {
            return this.tag.getHistoricalBytes();
        }
        return this.tag.getHiLayerResponse();
    }

    public int getMaxTranceiveLength() {
        return this.tag.getMaxTransceiveLength();
    }

    public boolean isConnected() {
        return this.tag.isConnected();
    }

    public void setSecureMessaging(SecureMessaging sm) {
        this.sm = sm;
    }

    public boolean isSmActive() {
        if (this.sm != null) {
            return true;
        }
        return false;
    }

    public ResponseAPDU transceive(CommandAPDU cmd) throws IOException, SecureMessagingException, LostChannelException {
        if (!this.tag.isConnected()) {
            if (this.generateLogDebug) {
                Log.d(TAG, "Connecting Tag for transceiving!");
            }
            this.tag.connect();
        }
        if (this.generateLogDebug) {
            Log.d(TAG, "sent (PLAIN):\n" + HexString.bufferToHex(cmd.getBytes()));
        }
        if (this.logger != null) {
            this.logger.log(Level.FINE, "sent (PLAIN):\n" + HexString.bufferToHex(cmd.getBytes()));
        }
        if (this.sm != null) {
            cmd = this.sm.wrap(cmd);
            if (this.logger != null) {
                this.logger.log(Level.FINE, "sent (SM):\n" + HexString.bufferToHex(cmd.getBytes()));
            }
        }
        ResponseAPDU rapdu = new ResponseAPDU(this.tag.transceive(cmd.getBytes()));
        if (this.sm != null) {
            if (this.logger != null) {
                this.logger.log(Level.FINE, "received (SM):\n" + HexString.bufferToHex(rapdu.getBytes()));
            }
            if (rapdu.ChannelLost()) {
                throw new LostChannelException("Canal securizado PERDIDO");
            }
            rapdu = this.sm.unwrap(rapdu);
        }
        if (this.generateLogDebug) {
            Log.d(TAG, "received (PLAIN): \n" + HexString.bufferToHex(rapdu.getBytes()));
        }
        if (this.logger != null) {
            this.logger.log(Level.FINE, "received (PLAIN):\n" + HexString.bufferToHex(rapdu.getBytes()));
        }
        return rapdu;
    }
}
