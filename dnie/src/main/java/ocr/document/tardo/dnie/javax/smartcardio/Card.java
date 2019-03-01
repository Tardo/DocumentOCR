package javax.smartcardio;

public abstract class Card {
    public abstract void beginExclusive() throws CardException;

    public abstract void disconnect(boolean z) throws CardException;

    public abstract void endExclusive() throws CardException;

    public abstract ATR getATR();

    public abstract CardChannel getBasicChannel();

    public abstract String getProtocol();

    public abstract CardChannel openLogicalChannel() throws CardException;

    public abstract byte[] transmitControlCommand(int i, byte[] bArr) throws CardException;

    protected Card() {
    }
}
