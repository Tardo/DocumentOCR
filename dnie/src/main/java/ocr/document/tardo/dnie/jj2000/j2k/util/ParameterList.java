package jj2000.j2k.util;

import java.util.Enumeration;
import java.util.Properties;

public class ParameterList extends Properties {
    public ParameterList(ParameterList def) {
        super(def);
    }

    public ParameterList getDefaultParameterList() {
        return (ParameterList) this.defaults;
    }

    public void parseArgs(String[] argv) {
        int k = -1;
        do {
            k++;
            if (k >= argv.length) {
                return;
            }
        } while (argv[k].length() <= 0);
        char c = argv[k].charAt(0);
        if (c != '-' && c != '+') {
            throw new StringFormatException("Argument list does not start with an option: " + argv[k]);
        } else if (argv[k].length() < 2 || !Character.isDigit(argv[k].charAt(1))) {
            StringBuffer pvalue = new StringBuffer();
            while (k < argv.length) {
                if (argv[k].length() <= 1) {
                    throw new StringFormatException("Option \"" + argv[k] + "\" is too short.");
                }
                c = argv[k].charAt(0);
                int k2 = k + 1;
                String pname = argv[k];
                pvalue.setLength(0);
                if (k2 >= argv.length) {
                    String str;
                    if (c == '-') {
                        str = "on";
                    } else {
                        str = "off";
                    }
                    pvalue.append(str);
                    k = k2;
                } else {
                    char c2 = argv[k2].charAt(0);
                    if (c2 == '-' || c2 == '+') {
                        if (argv[k2].length() <= 1) {
                            throw new StringFormatException("Option or argument \"" + argv[k2] + "\" too short");
                        } else if (!Character.isDigit(argv[k2].charAt(1))) {
                            pvalue.append(c == '-' ? "on" : "off");
                        }
                    }
                    if (pvalue.length() != 0) {
                        k = k2;
                    } else if (c == '+') {
                        throw new StringFormatException("Boolean option \"" + pname + "\" has a value");
                    } else {
                        k = k2 + 1;
                        pvalue.append(argv[k2]);
                        while (k < argv.length) {
                            if (argv[k].length() == 0) {
                                k++;
                            } else {
                                c = argv[k].charAt(0);
                                if (c == '-' || c == '+') {
                                    if (argv[k].length() > 1) {
                                        if (!Character.isDigit(argv[k].charAt(1))) {
                                            break;
                                        }
                                    }
                                    throw new StringFormatException("Option or argument \"" + argv[k] + "\" too short");
                                }
                                pvalue.append(' ');
                                k2 = k + 1;
                                pvalue.append(argv[k]);
                                k = k2;
                            }
                        }
                    }
                }
                if (get(pname.substring(1)) != null) {
                    throw new StringFormatException("Option \"" + pname + "\" appears more than once");
                }
                put(pname.substring(1), pvalue.toString());
            }
        } else {
            throw new StringFormatException("Numeric option name: " + argv[k]);
        }
    }

    public String getParameter(String pname) {
        String pval = (String) get(pname);
        if (pval != null || this.defaults == null) {
            return pval;
        }
        return this.defaults.getProperty(pname);
    }

    public boolean getBooleanParameter(String pname) {
        String s = getParameter(pname);
        if (s == null) {
            throw new IllegalArgumentException("No parameter with name " + pname);
        } else if (s.equals("on")) {
            return true;
        } else {
            if (s.equals("off")) {
                return false;
            }
            throw new StringFormatException("Parameter \"" + pname + "\" is not boolean: " + s);
        }
    }

    public int getIntParameter(String pname) {
        String s = getParameter(pname);
        if (s == null) {
            throw new IllegalArgumentException("No parameter with name " + pname);
        }
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new NumberFormatException("Parameter \"" + pname + "\" is not integer: " + e.getMessage());
        }
    }

    public float getFloatParameter(String pname) {
        String s = getParameter(pname);
        if (s == null) {
            throw new IllegalArgumentException("No parameter with name " + pname);
        }
        try {
            return new Float(s).floatValue();
        } catch (NumberFormatException e) {
            throw new NumberFormatException("Parameter \"" + pname + "\" is not floating-point: " + e.getMessage());
        }
    }

    public void checkList(char prfx, String[] plist) {
        Enumeration args = propertyNames();
        while (args.hasMoreElements()) {
            String val = (String) args.nextElement();
            if (val.length() > 0 && val.charAt(0) == prfx) {
                boolean isvalid = false;
                if (plist != null) {
                    for (int i = plist.length - 1; i >= 0; i--) {
                        if (val.equals(plist[i])) {
                            isvalid = true;
                            break;
                        }
                    }
                }
                if (!isvalid) {
                    throw new IllegalArgumentException("Option '" + val + "' is " + "not a valid one.");
                }
            }
        }
    }

    public void checkList(char[] prfxs, String[] plist) {
        Enumeration args = propertyNames();
        String strprfxs = new String(prfxs);
        while (args.hasMoreElements()) {
            String val = (String) args.nextElement();
            if (val.length() > 0 && strprfxs.indexOf(val.charAt(0)) == -1) {
                boolean isvalid = false;
                if (plist != null) {
                    for (int i = plist.length - 1; i >= 0; i--) {
                        if (val.equals(plist[i])) {
                            isvalid = true;
                            break;
                        }
                    }
                }
                if (!isvalid) {
                    throw new IllegalArgumentException("Option '" + val + "' is " + "not a valid one.");
                }
            }
        }
    }

    public static String[] toNameArray(String[][] pinfo) {
        if (pinfo == null) {
            return null;
        }
        String[] pnames = new String[pinfo.length];
        for (int i = pinfo.length - 1; i >= 0; i--) {
            pnames[i] = pinfo[i][0];
        }
        return pnames;
    }
}
