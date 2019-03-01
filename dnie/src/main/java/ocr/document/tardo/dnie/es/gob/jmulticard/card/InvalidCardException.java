package es.gob.jmulticard.card;

import es.gob.jmulticard.HexUtils;

public final class InvalidCardException extends CardException {
    private static final long serialVersionUID = 4888120866657775782L;
    private final Atr atr;
    private final byte[] badAtr;
    private final String name;

    public InvalidCardException(String expectedCardName, Atr expectedAtr, byte[] foundAtr) {
        String str;
        StringBuilder append = new StringBuilder().append("Se esperaba una tarjeta de tipo '").append(expectedCardName).append("' pero se encontro otra con ATR=");
        if (foundAtr == null) {
            str = "NULO";
        } else {
            str = HexUtils.hexify(foundAtr, true);
        }
        super(append.append(str).toString());
        this.atr = expectedAtr;
        this.name = expectedCardName;
        if (foundAtr != null) {
            this.badAtr = new byte[foundAtr.length];
            System.arraycopy(foundAtr, 0, this.badAtr, 0, this.badAtr.length);
            return;
        }
        this.badAtr = null;
    }

    public Atr getExpectedAtr() {
        return this.atr;
    }

    public String getExpectedCardName() {
        return this.name;
    }

    public byte[] getFoundAtr() {
        if (this.badAtr == null) {
            return null;
        }
        byte[] tmpAtr = new byte[this.badAtr.length];
        System.arraycopy(this.badAtr, 0, tmpAtr, 0, this.badAtr.length);
        return tmpAtr;
    }
}
