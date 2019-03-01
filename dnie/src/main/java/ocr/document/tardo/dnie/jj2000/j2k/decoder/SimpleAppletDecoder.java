package jj2000.j2k.decoder;

import java.applet.Applet;
import java.awt.BorderLayout;
import java.awt.Image;
import java.net.MalformedURLException;
import java.net.URL;
import jj2000.disp.ImgKeyListener;
import jj2000.disp.ImgMouseListener;
import jj2000.disp.ImgScrollPane;
import jj2000.j2k.util.ParameterList;

public class SimpleAppletDecoder extends Applet implements Runnable {
    private static String[][] pinfo = Decoder.getAllParameters();
    private Decoder dec;
    private boolean decStarted;
    private Thread decThread;
    private ImgScrollPane isp;
    private ParameterList pl;

    public void init() {
        int i;
        String param;
        ParameterList defpl = new ParameterList();
        for (i = pinfo.length - 1; i >= 0; i--) {
            if (pinfo[i][3] != null) {
                defpl.put(pinfo[i][0], pinfo[i][3]);
            }
        }
        this.pl = new ParameterList(defpl);
        for (i = 0; i < pinfo.length; i++) {
            param = getParameter(pinfo[i][0]);
            if (param != null) {
                this.pl.put(pinfo[i][0], param);
            }
        }
        param = this.pl.getParameter("i");
        if (param != null) {
            try {
                this.pl.put("i", new URL(getDocumentBase(), param).toExternalForm());
                if (this.pl.getParameter("o") != null) {
                    throw new IllegalArgumentException("Can not specify output files for applet");
                }
                setLayout(new BorderLayout());
                this.isp = new ImgScrollPane(0);
                add(this.isp, "Center");
                validate();
                setVisible(true);
                this.decThread = new Thread(this);
                this.decStarted = false;
                return;
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Malformed URL in parameter 'i'");
            }
        }
        throw new IllegalArgumentException("Missing input");
    }

    public void start() {
        if (!this.decStarted) {
            this.decStarted = true;
            this.decThread.start();
        }
    }

    public void stop() {
    }

    public void destroy() {
        if (this.decStarted) {
            while (this.decThread != null && this.decThread.isAlive()) {
                try {
                    Thread.currentThread();
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                }
            }
            this.decThread = null;
        }
    }

    public void run() {
        if (this.dec == null) {
            int status;
            showStatus("Initializing JJ2000 decoder...");
            this.dec = new Decoder(this.pl, this.isp);
            this.dec.setChildProcess(true);
            showStatus("Decoding...");
            this.dec.run();
            Image img = this.isp.getImage();
            do {
                status = this.isp.checkImage(img, null);
                if ((status & 64) != 0) {
                    showStatus("An unknown error occurred while producing the image");
                    return;
                } else if ((status & 128) != 0) {
                    showStatus("Image production was aborted for some unknown reason");
                } else if ((status & 32) != 0) {
                    showStatus("Done.");
                } else {
                    try {
                        Thread.currentThread();
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                    }
                }
            } while ((status & 224) == 0);
            if ((status & 64) == 0) {
                ImgMouseListener iml = new ImgMouseListener(this.isp);
                this.isp.addKeyListener(new ImgKeyListener(this.isp, this.dec));
                this.isp.addMouseListener(iml);
                this.isp.addMouseMotionListener(iml);
            }
        }
    }

    public String getAppletInfo() {
        return "JJ2000's JPEG 2000 simple applet decoder\nVersion: 5.1\nCopyright:\n\nThis software module was originally developed by Raphaël Grosbois and Diego Santa Cruz (Swiss Federal Institute of Technology-EPFL); Joel Askelöf (Ericsson Radio Systems AB); and Bertrand Berthelot, David Bouchard, Félix Henry, Gerard Mozelle and Patrice Onno (Canon Research Centre France S.A) in the course of development of the JPEG 2000 standard as specified by ISO/IEC 15444 (JPEG 2000 Standard). This software module is an implementation of a part of the JPEG 2000 Standard. Swiss Federal Institute of Technology-EPFL, Ericsson Radio Systems AB and Canon Research Centre France S.A (collectively JJ2000 Partners) agree not to assert against ISO/IEC and users of the JPEG 2000 Standard (Users) any of their rights under the copyright, not including other intellectual property rights, for this software module with respect to the usage by ISO/IEC and Users of this software module or modifications thereof for use in hardware or software products claiming conformance to the JPEG 2000 Standard. Those intending to use this software module in hardware or software products are advised that their use may infringe existing patents. The original developers of this software module, JJ2000 Partners and ISO/IEC assume no liability for use of this software module or modifications thereof. No license or right to this software module is granted for non JPEG 2000 Standard conforming products. JJ2000 Partners have full right to use this software module for his/her own purpose, assign or donate this software module to any third party and to inhibit third parties from using this software module for non JPEG 2000 Standard conforming products. This copyright notice must be included in all copies or derivative works of this software module.\n\nCopyright (c) 1999/2000 JJ2000 Partners.\nSend bug reports to: jj2000-bugs@ltssg3.epfl.ch\n";
    }

    public String[][] getParameterInfo() {
        return pinfo;
    }
}
