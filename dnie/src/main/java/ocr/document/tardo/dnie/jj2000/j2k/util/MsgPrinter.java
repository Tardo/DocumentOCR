package jj2000.j2k.util;

import java.io.PrintWriter;

public class MsgPrinter {
    private static final int IS_EOS = -1;
    private static final int IS_NEWLINE = -2;
    public int lw;

    public MsgPrinter(int linewidth) {
        this.lw = linewidth;
    }

    public int getLineWidth() {
        return this.lw;
    }

    public void setLineWidth(int linewidth) {
        if (linewidth < 1) {
            throw new IllegalArgumentException();
        }
        this.lw = linewidth;
    }

    public void print(PrintWriter out, int flind, int ind, String msg) {
        int start = 0;
        int pend = 0;
        int efflw = this.lw - flind;
        int lind = flind;
        while (true) {
            int end = nextLineEnd(msg, pend);
            if (end == -1) {
                break;
            }
            int i;
            if (end == -2) {
                for (i = 0; i < lind; i++) {
                    out.print(" ");
                }
                out.println(msg.substring(start, pend));
                if (nextWord(msg, pend) == msg.length()) {
                    break;
                }
            } else if (efflw > end - pend) {
                efflw -= end - pend;
                pend = end;
            } else {
                for (i = 0; i < lind; i++) {
                    out.print(" ");
                }
                if (start == pend) {
                    out.println(msg.substring(start, end));
                    pend = end;
                } else {
                    out.println(msg.substring(start, pend));
                }
            }
            lind = ind;
            efflw = this.lw - ind;
            start = nextWord(msg, pend);
            pend = start;
            if (start == -1) {
                break;
            }
        }
        out.println("");
        start = pend;
        if (pend != start) {
            for (i = 0; i < lind; i++) {
                out.print(" ");
            }
            out.println(msg.substring(start, pend));
        }
    }

    private int nextLineEnd(String str, int from) {
        int len = str.length();
        char c = '\u0000';
        while (from < len) {
            c = str.charAt(from);
            if (c == '\n' || !Character.isWhitespace(c)) {
                break;
            }
            from++;
        }
        if (c == '\n') {
            return -2;
        }
        if (from >= len) {
            return -1;
        }
        while (from < len && !Character.isWhitespace(str.charAt(from))) {
            from++;
        }
        return from;
    }

    private int nextWord(String str, int from) {
        int len = str.length();
        char c = '\u0000';
        while (from < len) {
            c = str.charAt(from);
            if (c == '\n' || !Character.isWhitespace(c)) {
                break;
            }
            from++;
        }
        if (from >= len) {
            return -1;
        }
        if (c == '\n') {
            return from + 1;
        }
        return from;
    }
}
