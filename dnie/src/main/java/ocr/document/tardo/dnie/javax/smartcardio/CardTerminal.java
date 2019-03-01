package javax.smartcardio;

public abstract class CardTerminal {
    public abstract Card connect(String str) throws CardException;

    public abstract String getName();

    public abstract boolean isCardPresent() throws CardException;

    public abstract boolean waitForCardAbsent(long j) throws CardException;

    public abstract boolean waitForCardPresent(long j) throws CardException;

    protected CardTerminal() {
    }
}
