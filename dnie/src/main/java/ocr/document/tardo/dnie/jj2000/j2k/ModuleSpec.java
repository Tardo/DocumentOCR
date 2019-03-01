package jj2000.j2k;

import java.lang.reflect.Array;
import java.util.Enumeration;
import java.util.Hashtable;
import jj2000.j2k.image.Coord;

public class ModuleSpec implements Cloneable {
    public static final byte SPEC_COMP_DEF = (byte) 1;
    public static final byte SPEC_DEF = (byte) 0;
    public static final byte SPEC_TILE_COMP = (byte) 3;
    public static final byte SPEC_TILE_DEF = (byte) 2;
    public static final byte SPEC_TYPE_COMP = (byte) 0;
    public static final byte SPEC_TYPE_TILE = (byte) 1;
    public static final byte SPEC_TYPE_TILE_COMP = (byte) 2;
    protected Object[] compDef = null;
    protected Object def = null;
    protected int nComp = 0;
    protected int nTiles = 0;
    protected int specType;
    protected byte[][] specValType;
    protected Hashtable tileCompVal;
    protected Object[] tileDef = null;

    public ModuleSpec getCopy() {
        return (ModuleSpec) clone();
    }

    protected Object clone() {
        try {
            int t;
            ModuleSpec ms = (ModuleSpec) super.clone();
            ms.specValType = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{this.nTiles, this.nComp});
            for (t = 0; t < this.nTiles; t++) {
                for (int c = 0; c < this.nComp; c++) {
                    ms.specValType[t][c] = this.specValType[t][c];
                }
            }
            if (this.tileDef != null) {
                ms.tileDef = new Object[this.nTiles];
                for (t = 0; t < this.nTiles; t++) {
                    ms.tileDef[t] = this.tileDef[t];
                }
            }
            if (this.tileCompVal != null) {
                ms.tileCompVal = new Hashtable();
                Enumeration e = this.tileCompVal.keys();
                while (e.hasMoreElements()) {
                    String tmpKey = (String) e.nextElement();
                    ms.tileCompVal.put(tmpKey, this.tileCompVal.get(tmpKey));
                }
            }
            return ms;
        } catch (CloneNotSupportedException e2) {
            throw new Error("Error when cloning ModuleSpec instance");
        }
    }

    public void rotate90(Coord anT) {
        int by;
        int bx;
        byte[][] tmpsvt = new byte[this.nTiles][];
        Coord bnT = new Coord(anT.f37y, anT.f36x);
        for (by = 0; by < bnT.f37y; by++) {
            for (bx = 0; bx < bnT.f36x; bx++) {
                int ax = (bnT.f37y - by) - 1;
                tmpsvt[(anT.f36x * bx) + ax] = this.specValType[(bnT.f36x * by) + bx];
            }
        }
        this.specValType = tmpsvt;
        if (this.tileDef != null) {
            Object[] tmptd = new Object[this.nTiles];
            for (by = 0; by < bnT.f37y; by++) {
                for (bx = 0; bx < bnT.f36x; bx++) {
                    ax = (bnT.f37y - by) - 1;
                    tmptd[(anT.f36x * bx) + ax] = this.tileDef[(bnT.f36x * by) + bx];
                }
            }
            this.tileDef = tmptd;
        }
        if (this.tileCompVal != null && this.tileCompVal.size() > 0) {
            Hashtable tmptcv = new Hashtable();
            Enumeration e = this.tileCompVal.keys();
            while (e.hasMoreElements()) {
                String tmpKey = (String) e.nextElement();
                Object tmpVal = this.tileCompVal.get(tmpKey);
                int i1 = tmpKey.indexOf(116);
                int i2 = tmpKey.indexOf(99);
                int btIdx = new Integer(tmpKey.substring(i1 + 1, i2)).intValue();
                tmptcv.put("t" + (((bnT.f37y - (btIdx / bnT.f36x)) - 1) + (anT.f36x * (btIdx % bnT.f36x))) + tmpKey.substring(i2), tmpVal);
            }
            this.tileCompVal = tmptcv;
        }
    }

    public ModuleSpec(int nt, int nc, byte type) {
        this.nTiles = nt;
        this.nComp = nc;
        this.specValType = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{nt, nc});
        switch (type) {
            case (byte) 0:
                this.specType = 0;
                return;
            case (byte) 1:
                this.specType = 1;
                return;
            case (byte) 2:
                this.specType = 2;
                return;
            default:
                return;
        }
    }

    public void setDefault(Object value) {
        this.def = value;
    }

    public Object getDefault() {
        return this.def;
    }

    public void setCompDef(int c, Object value) {
        if (this.specType == 1) {
            throw new Error("Option whose value is '" + value + "' cannot be " + "specified for components as it is a 'tile only' specific " + "option");
        }
        if (this.compDef == null) {
            this.compDef = new Object[this.nComp];
        }
        for (int i = 0; i < this.nTiles; i++) {
            if (this.specValType[i][c] < (byte) 1) {
                this.specValType[i][c] = (byte) 1;
            }
        }
        this.compDef[c] = value;
    }

    public Object getCompDef(int c) {
        if (this.specType == 1) {
            throw new Error("Illegal use of ModuleSpec class");
        } else if (this.compDef == null || this.compDef[c] == null) {
            return getDefault();
        } else {
            return this.compDef[c];
        }
    }

    public void setTileDef(int t, Object value) {
        if (this.specType == 0) {
            throw new Error("Option whose value is '" + value + "' cannot be " + "specified for tiles as it is a 'component only' specific " + "option");
        }
        if (this.tileDef == null) {
            this.tileDef = new Object[this.nTiles];
        }
        for (int i = 0; i < this.nComp; i++) {
            if (this.specValType[t][i] < (byte) 2) {
                this.specValType[t][i] = (byte) 2;
            }
        }
        this.tileDef[t] = value;
    }

    public Object getTileDef(int t) {
        if (this.specType == 0) {
            throw new Error("Illegal use of ModuleSpec class");
        } else if (this.tileDef == null || this.tileDef[t] == null) {
            return getDefault();
        } else {
            return this.tileDef[t];
        }
    }

    public void setTileCompVal(int t, int c, Object value) {
        if (this.specType != 2) {
            String errMsg = "Option whose value is '" + value + "' cannot be " + "specified for ";
            switch (this.specType) {
                case 0:
                    errMsg = errMsg + "tiles as it is a 'component only' specific option";
                    break;
                case 1:
                    errMsg = errMsg + "components as it is a 'tile only' specific option";
                    break;
            }
            throw new Error(errMsg);
        }
        if (this.tileCompVal == null) {
            this.tileCompVal = new Hashtable();
        }
        this.specValType[t][c] = (byte) 3;
        this.tileCompVal.put("t" + t + "c" + c, value);
    }

    public Object getTileCompVal(int t, int c) {
        if (this.specType == 2) {
            return getSpec(t, c);
        }
        throw new Error("Illegal use of ModuleSpec class");
    }

    protected Object getSpec(int t, int c) {
        switch (this.specValType[t][c]) {
            case (byte) 0:
                return getDefault();
            case (byte) 1:
                return getCompDef(c);
            case (byte) 2:
                return getTileDef(t);
            case (byte) 3:
                return this.tileCompVal.get("t" + t + "c" + c);
            default:
                throw new IllegalArgumentException("Not recognized spec type");
        }
    }

    public byte getSpecValType(int t, int c) {
        return this.specValType[t][c];
    }

    public boolean isCompSpecified(int c) {
        if (this.compDef == null || this.compDef[c] == null) {
            return false;
        }
        return true;
    }

    public boolean isTileSpecified(int t) {
        if (this.tileDef == null || this.tileDef[t] == null) {
            return false;
        }
        return true;
    }

    public boolean isTileCompSpecified(int t, int c) {
        if (this.tileCompVal == null || this.tileCompVal.get("t" + t + "c" + c) == null) {
            return false;
        }
        return true;
    }

    public static final boolean[] parseIdx(String word, int maxIdx) {
        int nChar = word.length();
        char c = word.charAt(0);
        int idx = -1;
        int lastIdx = -1;
        boolean isDash = false;
        boolean[] idxSet = new boolean[maxIdx];
        for (int i = 1; i < nChar; i++) {
            int j;
            c = word.charAt(i);
            if (Character.isDigit(c)) {
                if (idx == -1) {
                    idx = 0;
                }
                idx = (idx * 10) + (c - 48);
            } else if (idx == -1 || !(c == ',' || c == '-')) {
                throw new IllegalArgumentException("Bad construction for parameter: " + word);
            } else if (idx < 0 || idx >= maxIdx) {
                throw new IllegalArgumentException("Out of range index in parameter `" + word + "' : " + idx);
            } else {
                if (c == ',') {
                    if (isDash) {
                        for (j = lastIdx + 1; j < idx; j++) {
                            idxSet[j] = true;
                        }
                    }
                    isDash = false;
                } else {
                    isDash = true;
                }
                idxSet[idx] = true;
                lastIdx = idx;
                idx = -1;
            }
        }
        if (idx < 0 || idx >= maxIdx) {
            throw new IllegalArgumentException("Out of range index in parameter `" + word + "' : " + idx);
        }
        if (isDash) {
            for (j = lastIdx + 1; j < idx; j++) {
                idxSet[j] = true;
            }
        }
        idxSet[idx] = true;
        return idxSet;
    }
}
