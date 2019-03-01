package javax.smartcardio;

import java.nio.ByteBuffer;

public abstract class CardChannel {
    public abstract void close() throws CardException;

    public abstract Card getCard();

    public abstract int getChannelNumber();

    public abstract int transmit(ByteBuffer byteBuffer, ByteBuffer byteBuffer2) throws CardException;

    public abstract ResponseAPDU transmit(CommandAPDU commandAPDU) throws CardException;

    protected CardChannel() {
    }
}
