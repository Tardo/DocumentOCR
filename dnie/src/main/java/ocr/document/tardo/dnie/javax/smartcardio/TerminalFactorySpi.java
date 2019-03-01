package javax.smartcardio;

public abstract class TerminalFactorySpi {
    protected abstract CardTerminals engineTerminals();

    protected TerminalFactorySpi() {
    }
}
