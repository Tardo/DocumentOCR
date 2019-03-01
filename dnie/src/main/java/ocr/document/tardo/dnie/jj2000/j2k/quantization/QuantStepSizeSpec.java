package jj2000.j2k.quantization;

import java.util.StringTokenizer;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class QuantStepSizeSpec extends ModuleSpec {
    public QuantStepSizeSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public QuantStepSizeSpec(int nt, int nc, byte type, ParameterList pl) {
        super(nt, nc, type);
        String param = pl.getParameter("Qstep");
        if (param == null) {
            throw new IllegalArgumentException("Qstep option not specified");
        }
        StringTokenizer stk = new StringTokenizer(param);
        byte curSpecType = (byte) 0;
        boolean[] tileSpec = null;
        boolean[] compSpec = null;
        while (stk.hasMoreTokens()) {
            String word = stk.nextToken().toLowerCase();
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
                        Float value = new Float(word);
                        if (value.floatValue() > 0.0f) {
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
                        }
                        throw new IllegalArgumentException("Normalized base step must be positive : " + value);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("Bad parameter for -Qstep option : " + word);
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
                setDefault(new Float(pl.getDefaultParameterList().getParameter("Qstep")));
                return;
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
}
