package jj2000.j2k;

import java.util.StringTokenizer;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class StringSpec extends ModuleSpec {
    public StringSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public StringSpec(int nt, int nc, byte type, String optName, String[] list, ParameterList pl) {
        super(nt, nc, type);
        String param = pl.getParameter(optName);
        boolean recognized = false;
        int i;
        if (param == null) {
            param = pl.getDefaultParameterList().getParameter(optName);
            for (i = list.length - 1; i >= 0; i--) {
                if (param.equalsIgnoreCase(list[i])) {
                    recognized = true;
                }
            }
            if (recognized) {
                setDefault(param);
                return;
            }
            throw new IllegalArgumentException("Default parameter of option -" + optName + " not" + " recognized: " + param);
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
                    recognized = false;
                    for (i = list.length - 1; i >= 0; i--) {
                        if (word.equalsIgnoreCase(list[i])) {
                            recognized = true;
                        }
                    }
                    if (recognized) {
                        if (curSpecType == (byte) 0) {
                            setDefault(word);
                        } else if (curSpecType == (byte) 2) {
                            for (i = tileSpec.length - 1; i >= 0; i--) {
                                if (tileSpec[i]) {
                                    setTileDef(i, word);
                                }
                            }
                        } else if (curSpecType == (byte) 1) {
                            for (i = compSpec.length - 1; i >= 0; i--) {
                                if (compSpec[i]) {
                                    setCompDef(i, word);
                                }
                            }
                        } else {
                            for (i = tileSpec.length - 1; i >= 0; i--) {
                                int j = compSpec.length - 1;
                                while (j >= 0) {
                                    if (tileSpec[i] && compSpec[j]) {
                                        setTileCompVal(i, j, word);
                                    }
                                    j--;
                                }
                            }
                        }
                        curSpecType = (byte) 0;
                        tileSpec = null;
                        compSpec = null;
                        break;
                    }
                    throw new IllegalArgumentException("Default parameter of option -" + optName + " not" + " recognized: " + word);
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
                for (i = list.length - 1; i >= 0; i--) {
                    if (param.equalsIgnoreCase(list[i])) {
                        recognized = true;
                    }
                }
                if (recognized) {
                    setDefault(param);
                    return;
                }
                throw new IllegalArgumentException("Default parameter of option -" + optName + " not" + " recognized: " + param);
            }
            setDefault(getSpec(0, 0));
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
}
