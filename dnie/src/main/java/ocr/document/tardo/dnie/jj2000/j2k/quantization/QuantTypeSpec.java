package jj2000.j2k.quantization;

import java.util.StringTokenizer;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.util.ParameterList;
import org.bouncycastle.asn1.eac.EACTags;

public class QuantTypeSpec extends ModuleSpec {
    public QuantTypeSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
    }

    public QuantTypeSpec(int nt, int nc, byte type, ParameterList pl) {
        super(nt, nc, type);
        String param = pl.getParameter("Qtype");
        if (param == null) {
            if (pl.getBooleanParameter("lossless")) {
                setDefault("reversible");
                return;
            } else {
                setDefault("expounded");
                return;
            }
        }
        StringTokenizer stk = new StringTokenizer(param);
        byte curSpecValType = (byte) 0;
        boolean[] tileSpec = null;
        boolean[] compSpec = null;
        while (stk.hasMoreTokens()) {
            String word = stk.nextToken().toLowerCase();
            switch (word.charAt(0)) {
                case EACTags.WRAPPER /*99*/:
                    compSpec = ModuleSpec.parseIdx(word, this.nComp);
                    if (curSpecValType != (byte) 2) {
                        curSpecValType = (byte) 1;
                        break;
                    } else {
                        curSpecValType = (byte) 3;
                        break;
                    }
                case EACTags.FMD_TEMPLATE /*100*/:
                case EACTags.CARDHOLDER_RELATIVE_DATA /*101*/:
                case 'r':
                    if (word.equalsIgnoreCase("reversible") || word.equalsIgnoreCase("derived") || word.equalsIgnoreCase("expounded")) {
                        if (!pl.getBooleanParameter("lossless") || (!word.equalsIgnoreCase("derived") && !word.equalsIgnoreCase("expounded"))) {
                            if (curSpecValType == (byte) 0) {
                                setDefault(word);
                            } else if (curSpecValType == (byte) 2) {
                                for (i = tileSpec.length - 1; i >= 0; i--) {
                                    if (tileSpec[i]) {
                                        setTileDef(i, word);
                                    }
                                }
                            } else if (curSpecValType == (byte) 1) {
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
                            curSpecValType = (byte) 0;
                            tileSpec = null;
                            compSpec = null;
                            break;
                        }
                        throw new IllegalArgumentException("Cannot use non reversible quantization with '-lossless' option");
                    }
                    throw new IllegalArgumentException("Unknown parameter for '-Qtype' option: " + word);
                case 't':
                    tileSpec = ModuleSpec.parseIdx(word, this.nTiles);
                    if (curSpecValType != (byte) 1) {
                        curSpecValType = (byte) 2;
                        break;
                    } else {
                        curSpecValType = (byte) 3;
                        break;
                    }
                default:
                    throw new IllegalArgumentException("Unknown parameter for '-Qtype' option: " + word);
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
                if (pl.getBooleanParameter("lossless")) {
                    setDefault("reversible");
                    return;
                } else {
                    setDefault("expounded");
                    return;
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

    public boolean isDerived(int t, int c) {
        if (((String) getTileCompVal(t, c)).equals("derived")) {
            return true;
        }
        return false;
    }

    public boolean isReversible(int t, int c) {
        if (((String) getTileCompVal(t, c)).equals("reversible")) {
            return true;
        }
        return false;
    }

    public boolean isFullyReversible() {
        if (!((String) getDefault()).equals("reversible")) {
            return false;
        }
        for (int t = this.nTiles - 1; t >= 0; t--) {
            for (int c = this.nComp - 1; c >= 0; c--) {
                if (this.specValType[t][c] != (byte) 0) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean isFullyNonReversible() {
        for (int t = this.nTiles - 1; t >= 0; t--) {
            for (int c = this.nComp - 1; c >= 0; c--) {
                if (((String) getSpec(t, c)).equals("reversible")) {
                    return false;
                }
            }
        }
        return true;
    }
}
