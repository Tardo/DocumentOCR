package jj2000.j2k;

import java.util.StringTokenizer;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class IntegerSpec extends ModuleSpec {
    protected static int MAX_INT = Integer.MAX_VALUE;

    public IntegerSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public IntegerSpec(int nt, int nc, byte type, ParameterList pl, String optName) {
        super(nt, nc, type);
        String param = pl.getParameter(optName);
        if (param == null) {
            param = pl.getDefaultParameterList().getParameter(optName);
            try {
                setDefault(new Integer(param));
                return;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Non recognized value for option -" + optName + ": " + param);
            }
        }
        StringTokenizer stk = new StringTokenizer(param);
        byte curSpecType = (byte) 0;
        boolean[] tileSpec = null;
        boolean[] compSpec = null;
        while (stk.hasMoreTokens()) {
            String word = stk.nextToken();
            switch (word.charAt(0)) {
                case EACTags.WRAPPER /*99*/:
                    compSpec = ModuleSpec.parseIdx(word, this.nComp);
                    if (curSpecType != (byte) 2) {
                        curSpecType = (byte) 1;
                        break;
                    } else {
                        curSpecType = (byte) 3;
                        break;
                    }
                case 't':
                    tileSpec = ModuleSpec.parseIdx(word, this.nTiles);
                    if (curSpecType != (byte) 1) {
                        curSpecType = (byte) 2;
                        break;
                    } else {
                        curSpecType = (byte) 3;
                        break;
                    }
                default:
                    try {
                        Integer value = new Integer(word);
                        if (curSpecType == (byte) 0) {
                            setDefault(value);
                        } else if (curSpecType == (byte) 2) {
                            for (i = tileSpec.length - 1; i >= 0; i--) {
                                if (tileSpec[i]) {
                                    setTileDef(i, value);
                                }
                            }
                        } else if (curSpecType == (byte) 1) {
                            for (i = compSpec.length - 1; i >= 0; i--) {
                                if (compSpec[i]) {
                                    setCompDef(i, value);
                                }
                            }
                        } else {
                            for (i = tileSpec.length - 1; i >= 0; i--) {
                                int j = compSpec.length - 1;
                                while (j >= 0) {
                                    if (tileSpec[i] && compSpec[j]) {
                                        setTileCompVal(i, j, value);
                                    }
                                    j--;
                                }
                            }
                        }
                        curSpecType = (byte) 0;
                        tileSpec = null;
                        compSpec = null;
                        break;
                    } catch (NumberFormatException e2) {
                        throw new IllegalArgumentException("Non recognized value for option -" + optName + ": " + word);
                    }
            }
        }
        if (getDefault() == null) {
            int t;
            int c;
            int ndefspec = 0;
            for (t = nt - 1; t >= 0; t--) {
                for (c = nc - 1; c >= 0; c--) {
                    if (this.specValType[t][c] == (byte) 0) {
                        ndefspec++;
                    }
                }
            }
            if (ndefspec != 0) {
                param = pl.getDefaultParameterList().getParameter(optName);
                try {
                    setDefault(new Integer(param));
                    return;
                } catch (NumberFormatException e3) {
                    throw new IllegalArgumentException("Non recognized value for option -" + optName + ": " + param);
                }
            }
            setDefault(getTileCompVal(0, 0));
            switch (this.specValType[0][0]) {
                case (byte) 1:
                    for (t = nt - 1; t >= 0; t--) {
                        if (this.specValType[t][0] == (byte) 1) {
                            this.specValType[t][0] = (byte) 0;
                        }
                    }
                    this.compDef[0] = null;
                    return;
                case (byte) 2:
                    for (c = nc - 1; c >= 0; c--) {
                        if (this.specValType[0][c] == (byte) 2) {
                            this.specValType[0][c] = (byte) 0;
                        }
                    }
                    this.tileDef[0] = null;
                    return;
                case (byte) 3:
                    this.specValType[0][0] = (byte) 0;
                    this.tileCompVal.put("t0c0", null);
                    return;
                default:
                    return;
            }
        }
    }

    public int getMax() {
        int max = ((Integer) this.def).intValue();
        for (int t = 0; t < this.nTiles; t++) {
            for (int c = 0; c < this.nComp; c++) {
                int tmp = ((Integer) getSpec(t, c)).intValue();
                if (max < tmp) {
                    max = tmp;
                }
            }
        }
        return max;
    }

    public int getMin() {
        int min = ((Integer) this.def).intValue();
        for (int t = 0; t < this.nTiles; t++) {
            for (int c = 0; c < this.nComp; c++) {
                int tmp = ((Integer) getSpec(t, c)).intValue();
                if (min > tmp) {
                    min = tmp;
                }
            }
        }
        return min;
    }

    public int getMaxInComp(int c) {
        int max = 0;
        for (int t = 0; t < this.nTiles; t++) {
            int tmp = ((Integer) getSpec(t, c)).intValue();
            if (max < tmp) {
                max = tmp;
            }
        }
        return max;
    }

    public int getMinInComp(int c) {
        int min = MAX_INT;
        for (int t = 0; t < this.nTiles; t++) {
            int tmp = ((Integer) getSpec(t, c)).intValue();
            if (min > tmp) {
                min = tmp;
            }
        }
        return min;
    }

    public int getMaxInTile(int t) {
        int max = 0;
        for (int c = 0; c < this.nComp; c++) {
            int tmp = ((Integer) getSpec(t, c)).intValue();
            if (max < tmp) {
                max = tmp;
            }
        }
        return max;
    }

    public int getMinInTile(int t) {
        int min = MAX_INT;
        for (int c = 0; c < this.nComp; c++) {
            int tmp = ((Integer) getSpec(t, c)).intValue();
            if (min > tmp) {
                min = tmp;
            }
        }
        return min;
    }
}
