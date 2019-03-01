package jj2000.j2k.entropy;

import java.util.StringTokenizer;
import java.util.Vector;
import jj2000.j2k.IntegerSpec;
import jj2000.j2k.ModuleSpec;
import jj2000.j2k.util.ParameterList;

public class ProgressionSpec extends ModuleSpec {
    public ProgressionSpec(int nt, int nc, byte type) {
        super(nt, nc, type);
        if (type != (byte) 1) {
            throw new Error("Illegal use of class ProgressionSpec !");
        }
    }

    public ProgressionSpec(int nt, int nc, int nl, IntegerSpec dls, byte type, ParameterList pl) {
        super(nt, nc, type);
        String param = pl.getParameter("Aptype");
        int mode;
        if (param == null) {
            if (pl.getParameter("Rroi") == null) {
                mode = checkProgMode("res");
            } else {
                mode = checkProgMode("layer");
            }
            if (mode == -1) {
                throw new IllegalArgumentException("Unknown progression type : '" + param + "'");
            }
            Object prog = new Progression[1];
            prog[0] = new Progression(mode, 0, nc, 0, dls.getMax() + 1, nl);
            setDefault(prog);
            return;
        }
        int i;
        StringTokenizer stringTokenizer = new StringTokenizer(param);
        byte curSpecType = (byte) 0;
        boolean[] tileSpec = null;
        boolean needInteger = false;
        int intType = 0;
        Vector progression = new Vector();
        Progression curProg = null;
        while (stringTokenizer.hasMoreTokens()) {
            String word = stringTokenizer.nextToken();
            switch (word.charAt(0)) {
                case 't':
                    if (progression.size() > 0) {
                        curProg.ce = nc;
                        curProg.lye = nl;
                        curProg.re = dls.getMax() + 1;
                        prog = new Progression[progression.size()];
                        progression.copyInto(prog);
                        if (curSpecType == (byte) 0) {
                            setDefault(prog);
                        } else if (curSpecType == (byte) 2) {
                            for (i = tileSpec.length - 1; i >= 0; i--) {
                                if (tileSpec[i]) {
                                    setTileDef(i, prog);
                                }
                            }
                        }
                    }
                    progression.removeAllElements();
                    intType = -1;
                    needInteger = false;
                    tileSpec = ModuleSpec.parseIdx(word, this.nTiles);
                    curSpecType = (byte) 2;
                    break;
                default:
                    if (needInteger) {
                        try {
                            int tmp = new Integer(word).intValue();
                            switch (intType) {
                                case 0:
                                    if (tmp >= 0 && tmp <= dls.getMax() + 1) {
                                        curProg.rs = tmp;
                                        break;
                                    }
                                    throw new IllegalArgumentException("Invalid res_start in '-Aptype' option: " + tmp);
                                case 1:
                                    if (tmp >= 0 && tmp <= nc) {
                                        curProg.cs = tmp;
                                        break;
                                    }
                                    throw new IllegalArgumentException("Invalid comp_start in '-Aptype' option: " + tmp);
                                    break;
                                case 2:
                                    if (tmp >= 0) {
                                        if (tmp > nl) {
                                            tmp = nl;
                                        }
                                        curProg.lye = tmp;
                                        break;
                                    }
                                    throw new IllegalArgumentException("Invalid layer_end in '-Aptype' option: " + tmp);
                                case 3:
                                    if (tmp >= 0) {
                                        if (tmp > dls.getMax() + 1) {
                                            tmp = dls.getMax() + 1;
                                        }
                                        curProg.re = tmp;
                                        break;
                                    }
                                    throw new IllegalArgumentException("Invalid res_end in '-Aptype' option: " + tmp);
                                case 4:
                                    if (tmp >= 0) {
                                        if (tmp > nc) {
                                            tmp = nc;
                                        }
                                        curProg.ce = tmp;
                                        break;
                                    }
                                    throw new IllegalArgumentException("Invalid comp_end in '-Aptype' option: " + tmp);
                            }
                            if (intType < 4) {
                                intType++;
                                needInteger = true;
                                break;
                            } else if (intType == 4) {
                                intType = 0;
                                needInteger = false;
                                break;
                            } else {
                                throw new Error("Error in usage of 'Aptype' option: " + param);
                            }
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException("Progression order specification has missing parameters: " + param);
                        }
                    } else if (!needInteger) {
                        mode = checkProgMode(word);
                        if (mode != -1) {
                            needInteger = true;
                            intType = 0;
                            if (progression.size() == 0) {
                                curProg = new Progression(mode, 0, nc, 0, dls.getMax() + 1, nl);
                            } else {
                                curProg = new Progression(mode, 0, nc, 0, dls.getMax() + 1, nl);
                            }
                            progression.addElement(curProg);
                            break;
                        }
                        throw new IllegalArgumentException("Unknown progression type : '" + word + "'");
                    } else {
                        continue;
                    }
            }
        }
        if (progression.size() == 0) {
            if (pl.getParameter("Rroi") == null) {
                mode = checkProgMode("res");
            } else {
                mode = checkProgMode("layer");
            }
            if (mode == -1) {
                throw new IllegalArgumentException("Unknown progression type : '" + param + "'");
            }
            prog = new Progression[1];
            prog[0] = new Progression(mode, 0, nc, 0, dls.getMax() + 1, nl);
            setDefault(prog);
            return;
        }
        curProg.ce = nc;
        curProg.lye = nl;
        curProg.re = dls.getMax() + 1;
        prog = new Progression[progression.size()];
        progression.copyInto(prog);
        if (curSpecType == (byte) 0) {
            setDefault(prog);
        } else if (curSpecType == (byte) 2) {
            for (i = tileSpec.length - 1; i >= 0; i--) {
                if (tileSpec[i]) {
                    setTileDef(i, prog);
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
                if (pl.getParameter("Rroi") == null) {
                    mode = checkProgMode("res");
                } else {
                    mode = checkProgMode("layer");
                }
                if (mode == -1) {
                    throw new IllegalArgumentException("Unknown progression type : '" + param + "'");
                }
                prog = new Progression[1];
                prog[0] = new Progression(mode, 0, nc, 0, dls.getMax() + 1, nl);
                setDefault(prog);
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

    private int checkProgMode(String mode) {
        if (mode.equals("res")) {
            return 1;
        }
        if (mode.equals("layer")) {
            return 0;
        }
        if (mode.equals("pos-comp")) {
            return 3;
        }
        if (mode.equals("comp-pos")) {
            return 4;
        }
        if (mode.equals("res-pos")) {
            return 2;
        }
        return -1;
    }
}
