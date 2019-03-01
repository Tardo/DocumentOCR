package javax.smartcardio;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Permission;

public class CardPermission extends Permission {
    private static final int[] ARRAY_MASKS = new int[]{63, 1, 2, 4, 8, 16, 32};
    private static final String[] ARRAY_STRINGS = new String[]{"*", S_CONNECT, S_EXCLUSIVE, S_GET_BASIC_CHANNEL, S_OPEN_LOGICAL_CHANNEL, S_RESET, S_TRANSMIT_CONTROL};
    private static final int A_ALL = 63;
    private static final int A_CONNECT = 1;
    private static final int A_EXCLUSIVE = 2;
    private static final int A_GET_BASIC_CHANNEL = 4;
    private static final int A_OPEN_LOGICAL_CHANNEL = 8;
    private static final int A_RESET = 16;
    private static final int A_TRANSMIT_CONTROL = 32;
    private static final String S_ALL = "*";
    private static final String S_CONNECT = "connect";
    private static final String S_EXCLUSIVE = "exclusive";
    private static final String S_GET_BASIC_CHANNEL = "getBasicChannel";
    private static final String S_OPEN_LOGICAL_CHANNEL = "openLogicalChannel";
    private static final String S_RESET = "reset";
    private static final String S_TRANSMIT_CONTROL = "transmitControl";
    private static final long serialVersionUID = 7146787880530705613L;
    private volatile String actions;
    private transient int mask;

    public CardPermission(String terminalName, String actions) {
        super(terminalName);
        if (terminalName == null) {
            throw new NullPointerException();
        }
        this.mask = getMask(actions);
    }

    private static int getMask(String actions) {
        if (actions == null || actions.length() == 0) {
            throw new IllegalArgumentException("actions must not be empty");
        }
        int i;
        for (i = 0; i < ARRAY_STRINGS.length; i++) {
            if (actions == ARRAY_STRINGS[i]) {
                return ARRAY_MASKS[i];
            }
        }
        if (actions.endsWith(",")) {
            throw new IllegalArgumentException("Invalid actions: '" + actions + "'");
        }
        int mask = 0;
        String[] arr$ = actions.split(",");
        int len$ = arr$.length;
        int i$ = 0;
        while (i$ < len$) {
            String s = arr$[i$];
            i = 0;
            while (i < ARRAY_STRINGS.length) {
                if (ARRAY_STRINGS[i].equalsIgnoreCase(s)) {
                    mask |= ARRAY_MASKS[i];
                    i$++;
                } else {
                    i++;
                }
            }
            throw new IllegalArgumentException("Invalid action: '" + s + "'");
        }
        return mask;
    }

    private static String getActions(int mask) {
        if (mask == 63) {
            return "*";
        }
        boolean first = true;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ARRAY_MASKS.length; i++) {
            int action = ARRAY_MASKS[i];
            if ((mask & action) == action) {
                if (first) {
                    first = false;
                } else {
                    sb.append(",");
                }
                sb.append(ARRAY_STRINGS[i]);
            }
        }
        return sb.toString();
    }

    public String getActions() {
        if (this.actions == null) {
            this.actions = getActions(this.mask);
        }
        return this.actions;
    }

    public boolean implies(Permission permission) {
        if (!(permission instanceof CardPermission)) {
            return false;
        }
        CardPermission other = (CardPermission) permission;
        if ((this.mask & other.mask) != other.mask) {
            return false;
        }
        String thisName = getName();
        if (thisName.equals("*")) {
            return true;
        }
        if (thisName.equals(other.getName())) {
            return true;
        }
        return false;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CardPermission)) {
            return false;
        }
        CardPermission other = (CardPermission) obj;
        if (getName().equals(other.getName()) && this.mask == other.mask) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return getName().hashCode() + (this.mask * 31);
    }

    private void writeObject(ObjectOutputStream s) throws IOException {
        if (this.actions == null) {
            getActions();
        }
        s.defaultWriteObject();
    }

    private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
        s.defaultReadObject();
        this.mask = getMask(this.actions);
    }
}
