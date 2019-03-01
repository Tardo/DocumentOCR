package jj2000.j2k.util;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;

public class StreamMsgLogger implements MsgLogger {
    private PrintWriter err;
    private MsgPrinter mp;
    private PrintWriter out;

    public StreamMsgLogger(OutputStream outstr, OutputStream errstr, int lw) {
        this.out = new PrintWriter(outstr, true);
        this.err = new PrintWriter(errstr, true);
        this.mp = new MsgPrinter(lw);
    }

    public StreamMsgLogger(Writer outstr, Writer errstr, int lw) {
        this.out = new PrintWriter(outstr, true);
        this.err = new PrintWriter(errstr, true);
        this.mp = new MsgPrinter(lw);
    }

    public StreamMsgLogger(PrintWriter outstr, PrintWriter errstr, int lw) {
        this.out = outstr;
        this.err = errstr;
        this.mp = new MsgPrinter(lw);
    }

    public void printmsg(int sev, String msg) {
        String prefix;
        PrintWriter lout;
        switch (sev) {
            case 0:
                prefix = "[LOG]: ";
                lout = this.out;
                break;
            case 1:
                prefix = "[INFO]: ";
                lout = this.out;
                break;
            case 2:
                prefix = "[WARNING]: ";
                lout = this.err;
                break;
            case 3:
                prefix = "[ERROR]: ";
                lout = this.err;
                break;
            default:
                throw new IllegalArgumentException("Severity " + sev + " not valid.");
        }
        this.mp.print(lout, 0, prefix.length(), prefix + msg);
        lout.flush();
    }

    public void println(String str, int flind, int ind) {
        this.mp.print(this.out, flind, ind, str);
    }

    public void flush() {
        this.out.flush();
    }
}
