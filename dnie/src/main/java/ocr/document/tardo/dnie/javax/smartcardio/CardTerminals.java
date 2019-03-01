package javax.smartcardio;

import java.util.List;

public abstract class CardTerminals {

    public enum State {
        ALL,
        CARD_PRESENT,
        CARD_ABSENT,
        CARD_INSERTION,
        CARD_REMOVAL
    }

    public abstract List<CardTerminal> list(State state) throws CardException;

    public abstract boolean waitForChange(long j) throws CardException;

    protected CardTerminals() {
    }

    public List<CardTerminal> list() throws CardException {
        return list(State.ALL);
    }

    public CardTerminal getTerminal(String name) {
        if (name == null) {
            throw new NullPointerException();
        }
        try {
            for (CardTerminal terminal : list()) {
                if (terminal.getName().equals(name)) {
                    return terminal;
                }
            }
            return null;
        } catch (CardException e) {
            return null;
        }
    }

    public void waitForChange() throws CardException {
        waitForChange(0);
    }
}
