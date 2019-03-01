package es.gob.jmulticard.card;

import es.gob.jmulticard.HexUtils;
import java.util.Hashtable;
import java.util.Vector;

public final class Location {
    private static final Hashtable HEXBYTES = new Hashtable();
    private static final int MASTER_FILE_ID = 16128;
    private Vector path = new Vector();

    static {
        int i;
        String[] hex = new String[]{"a", "b", "c", "d", "e", "f"};
        for (i = 0; i < 10; i++) {
            HEXBYTES.put(String.valueOf(i), Integer.valueOf(String.valueOf(i)));
        }
        for (i = 10; i < 16; i++) {
            HEXBYTES.put(hex[i - 10], Integer.valueOf(String.valueOf(i)));
            HEXBYTES.put(hex[i - 10].toUpperCase(), Integer.valueOf(String.valueOf(i)));
        }
    }

    public Location(String absolutePath) {
        init(absolutePath);
    }

    public Location(String absolutePath, char pathSeparator) {
        StringBuffer auxPathVar = new StringBuffer();
        for (int i = 0; i < absolutePath.length(); i++) {
            if (absolutePath.charAt(i) != pathSeparator) {
                auxPathVar.append(absolutePath.charAt(i));
            }
        }
        init(auxPathVar.toString());
    }

    private Location(Vector path) {
        if (path != null) {
            int numElements = path.size();
            this.path = new Vector(numElements);
            for (int i = 0; i < numElements; i++) {
                this.path.insertElementAt(path.elementAt(i), i);
            }
        }
    }

    public Location getChild() {
        Location aux = new Location(this.path);
        if (aux.path == null || aux.path.size() <= 1) {
            return null;
        }
        aux.path.removeElementAt(0);
        return aux;
    }

    public byte[] getFile() {
        int address = ((Integer) this.path.elementAt(0)).intValue();
        return new byte[]{(byte) ((address >> 8) & 255), (byte) (address & 255)};
    }

    public byte[] getLastFilePath() {
        if (this.path.size() < 1) {
            return null;
        }
        int address = ((Integer) this.path.elementAt(this.path.size() - 1)).intValue();
        return new byte[]{(byte) ((address >> 8) & 255), (byte) (address & 255)};
    }

    private static boolean isValidPath(String absolutePath) {
        if (absolutePath.length() == 0) {
            return false;
        }
        String aux = absolutePath.toLowerCase();
        int i = 0;
        while (i < absolutePath.length()) {
            if ((aux.charAt(i) < '0' || aux.charAt(i) > '9') && (aux.charAt(i) < 'a' || aux.charAt(i) > 'f')) {
                return false;
            }
            i++;
        }
        return true;
    }

    private void init(String absolutePath) {
        if (absolutePath == null || "".equals(absolutePath.trim()) || absolutePath.trim().length() % 4 != 0) {
            throw new IllegalArgumentException("Un location valido debe estar compuesto por grupos de pares octetos.");
        } else if (isValidPath(absolutePath)) {
            for (int i = 0; i < absolutePath.length(); i += 4) {
                int mm = ((Integer) HEXBYTES.get(absolutePath.substring(i, i + 1))).intValue();
                int ml = ((Integer) HEXBYTES.get(absolutePath.substring(i + 1, i + 2))).intValue();
                int id = ((((Integer) HEXBYTES.get(absolutePath.substring(i + 3, i + 4))).intValue() + (((Integer) HEXBYTES.get(absolutePath.substring(i + 2, i + 3))).intValue() << 4)) + (ml << 8)) + ((mm << 4) << 8);
                if (id != MASTER_FILE_ID) {
                    this.path.addElement(Integer.valueOf(String.valueOf(id)));
                }
            }
        } else {
            throw new IllegalArgumentException("La ruta contiene caracteres no válidos.");
        }
    }

    public String toString() {
        StringBuffer buffer = new StringBuffer();
        if (!(this.path == null || this.path.isEmpty())) {
            buffer.append("3F00");
            for (int i = 0; i < this.path.size(); i++) {
                Integer integer = (Integer) this.path.elementAt(i);
                buffer.append('/').append(HexUtils.hexify(new byte[]{(byte) (integer.shortValue() >> 8), integer.byteValue()}, false));
            }
        }
        return buffer.toString();
    }
}
