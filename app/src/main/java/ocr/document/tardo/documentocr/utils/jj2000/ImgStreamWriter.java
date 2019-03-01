/*
 * CVS identifier:
 *
 * $Id: ImgWriterPPM.java,v 1.16 2002/07/25 15:10:14 grosbois Exp $
 *
 * Class:                   ImgWriterRawPPM
 *
 * Description:             Image writer for unsigned 8 bit data in
 *                          PPM file format.
 * 
 *
 *
 * COPYRIGHT:
 * 
 * This software module was originally developed by Rapha�l Grosbois and
 * Diego Santa Cruz (Swiss Federal Institute of Technology-EPFL); Joel
 * Askel�f (Ericsson Radio Systems AB); and Bertrand Berthelot, David
 * Bouchard, F�lix Henry, Gerard Mozelle and Patrice Onno (Canon Research
 * Centre France S.A) in the course of development of the JPEG2000
 * standard as specified by ISO/IEC 15444 (JPEG 2000 Standard). This
 * software module is an implementation of a part of the JPEG 2000
 * Standard. Swiss Federal Institute of Technology-EPFL, Ericsson Radio
 * Systems AB and Canon Research Centre France S.A (collectively JJ2000
 * Partners) agree not to assert against ISO/IEC and users of the JPEG
 * 2000 Standard (Users) any of their rights under the copyright, not
 * including other intellectual property rights, for this software module
 * with respect to the usage by ISO/IEC and Users of this software module
 * or modifications thereof for use in hardware or software products
 * claiming conformance to the JPEG 2000 Standard. Those intending to use
 * this software module in hardware or software products are advised that
 * their use may infringe existing patents. The original developers of
 * this software module, JJ2000 Partners and ISO/IEC assume no liability
 * for use of this software module or modifications thereof. No license
 * or right to this software module is granted for non JPEG 2000 Standard
 * conforming products. JJ2000 Partners have full right to use this
 * software module for his/her own purpose, assign or donate this
 * software module to any third party and to inhibit third parties from
 * using this software module for non JPEG 2000 Standard conforming
 * products. This copyright notice must be included in all copies or
 * derivative works of this software module.
 * 
 * Copyright (c) 1999/2000 JJ2000 Partners.
 * */
package ocr.document.tardo.documentocr.utils.jj2000;

import android.graphics.Bitmap;

import jj2000.j2k.image.*;
import jj2000.j2k.image.output.ImgWriter;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * This class writes 3 components from an image in 8 bit unsigned data to a
 * binary PPM file.
 *
 * <P>The size of the image that is written is the size of the source
 * image. No component subsampling is allowed in any of the components that
 * are written to the file.
 *
 * <P>Before writing, all coefficients are inversly level-shifted and then
 * "saturated" (they are limited * to the nominal dynamic range).<br>
 *
 * <u>Ex:</u> if the nominal range is 0-255, the following algorithm is
 * applied:<br>
 *
 * <tt>if coeff<0, output=0<br>
 *
 * if coeff>255, output=255<br>
 *
 * else output=coeff</tt>
 *
 * The write() methods of an object of this class may not be called
 * concurrently from different threads.
 *
 * <P>NOTE: This class is not thread safe, for reasons of internal buffering.
 * <P>Modified by D Westland so that it creates a Byte[] rather than a file
 * */
public class ImgStreamWriter extends ImgWriter {
	
    /** Value used to inverse level shift. One for each component */
    private int[] levShift = new int[3];

    /** Where to write the data */
	private final int CAPACITY = 5000000; //big enough for passport jpegs
	private ByteBuffer buffer = ByteBuffer.allocate(CAPACITY);

    /** The array of indexes of the components from where to get the data */
    private int cps[] = new int[3];

    /** The array of the number of fractional bits in the components of the
        source data */
    private int fb[] = new int[3];

    /** A DataBlk, just used to avoid allocating a new one each time
        it is needed */
    private DataBlkInt db = new DataBlkInt();

    /** The offset of the raw pixel data in the PPM file */
    private int offset;
    
    /** The line buffer. */
    // This makes the class not thrad safe
    // (but it is not the only one making it so)
    private byte buf[];

    /**
     * Creates a new writer to the specified File object, to write data from
     * the specified component.
     *
     * <p>The three components that will be written as R, G and B must be
     * specified through the b1, b2 and b3 arguments.</p>
     *
     *
     * @param imgSrc The source from where to get the image data to write.
     *
     * @param n1 The index of the first component from where to get the data,
     * that will be written as the red channel.
     *
     * @param n2 The index of the second component from where to get the data,
     * that will be written as the green channel.
     *
     * @param n3 The index of the third component from where to get the data,
     * that will be written as the green channel.
     *
     * @see DataBlk
     * */
    public ImgStreamWriter(BlkImgDataSrc imgSrc, 
			int n1,int n2,int n3) throws IOException{
        // Check that imgSrc is of the correct type
        // Check that the component index is valid
        if((n1<0) || (n1>=imgSrc.getNumComps()) ||
	   (n2<0) || (n2>=imgSrc.getNumComps()) ||
	   (n3<0) || (n3>=imgSrc.getNumComps()) ||
	   (imgSrc.getNomRangeBits(n1)>8) || 
	   (imgSrc.getNomRangeBits(n2)>8) ||
	   (imgSrc.getNomRangeBits(n3)>8)) {
            //throw new IllegalArgumentException("Invalid component indexes");
            // In case of Invalid component indexes, lets try with 0,0,0
            if(n1>=imgSrc.getNumComps())
                n1=0;
            if(n2>=imgSrc.getNumComps())
                n2=0;
            if(n3>=imgSrc.getNumComps())
                n3=0;
        }
        // Initialize
        w = imgSrc.getCompImgWidth(n1);
        h = imgSrc.getCompImgHeight(n1);
        // Check that all components have same width and height
        if(w!=imgSrc.getCompImgWidth(n2) ||
	   w!=imgSrc.getCompImgWidth(n3) ||
	   h!=imgSrc.getCompImgHeight(n2) ||
	   h!=imgSrc.getCompImgHeight(n3)) {
            throw new IllegalArgumentException("All components must have the"+
					       " same dimensions and no"+
					       " subsampling");
        }
        w = imgSrc.getImgWidth();
        h = imgSrc.getImgHeight();

        // Continue initialization
        buffer.clear();

        src = imgSrc;
        cps[0] = n1;
        cps[1] = n2;
        cps[2] = n3;
        fb[0] = imgSrc.getFixedPoint(n1);
        fb[1] = imgSrc.getFixedPoint(n2);
        fb[2] = imgSrc.getFixedPoint(n3);

        levShift[0] = 1<< (imgSrc.getNomRangeBits(n1)-1);
        levShift[1] = 1<< (imgSrc.getNomRangeBits(n2)-1);
        levShift[2] = 1<< (imgSrc.getNomRangeBits(n3)-1);
        
        writeHeaderInfo();
    }

              
    /**
     * Closes the underlying file or network connection to where the data is
     * written. Any call to other methods of the class become illegal after a
     * call to this one.
     *
     * @exception IOException If an I/O error occurs.
     * */
    public void close() throws IOException {
        src = null;
        db = null;
    }

    /**
     * Writes all buffered data to the file or resource.
     *
     * @exception IOException If an I/O error occurs.
     * */
    public void flush() throws IOException {
        // No flush needed here since we are using a RandomAccessFile Get rid
        // of line buffer (is this a good choice?)
        buf = null;
    }

    /**
     * Writes the data of the specified area to the file, coordinates are
     * relative to the current tile of the source. Before writing, the
     * coefficients are limited to the nominal range.
     *
     * <p>This method may not be called concurrently from different
     * threads.</p>
     *
     * <p>If the data returned from the BlkImgDataSrc source is progressive,
     * then it is requested over and over until it is not progressive
     * anymore.</p>
     *
     * @param ulx The horizontal coordinate of the upper-left corner of the
     * area to write, relative to the current tile.
     *
     * @param uly The vertical coordinate of the upper-left corner of the area
     * to write, relative to the current tile.
     *
     * @param w The width of the area to write.
     *
     * @param h The height of the area to write.
     *
     * @exception IOException If an I/O error occurs.
     * */
    public void write(int ulx, int uly, int w, int h) throws IOException{
        int k,j,i,c;
        // In local variables for faster access
        int fracbits;
        // variables used during coeff saturation
        int shift,tmp,maxVal;
        int tOffx, tOffy;      // Active tile offset in the X and Y direction
        
        // Active tiles in all components have same offset since they are at
        // same resolution (PPM does not support anything else)
        tOffx = src.getCompULX(cps[0]) -
            (int)Math.ceil(src.getImgULX()/(double)src.getCompSubsX(cps[0]));
        tOffy = src.getCompULY(cps[0]) -
            (int)Math.ceil(src.getImgULY()/(double)src.getCompSubsY(cps[0]));

        // Check the array size
        if(db.data!=null && db.data.length<w) {
            // A new one will be allocated by getInternCompData()
            db.data = null;
        }
        
        // Check the line buffer
        if(buf==null || buf.length<3*w) {
            buf = new byte[3*w];
        }

        // Write the data to the file
        // Write line by line
        for(i=0; i<h; i++) {
            // Write into buffer first loop over the three components and
            // write for each
            for(c=0; c<3; c++) {
                maxVal= (1<<src.getNomRangeBits(cps[c]))-1;
                shift = levShift[c];
            
                // Initialize db
                db.ulx = ulx;
                db.uly = uly+i;
                db.w = w;
                db.h = 1;

                // Request the data and make sure it is not progressive
                do {
                    db = (DataBlkInt)src.getInternCompData(db,cps[c]);
                } while (db.progressive);
                // Get the fracbits value
                fracbits = fb[c];
                // Write all bytes in the line
                if(fracbits==0) {
                    for(k=db.offset+w-1, j=3*w-1+c-2; j>=0; k--) {
                        tmp = db.data[k]+shift;
                        buf[j] = (byte)((tmp<0)? 0 : ((tmp>maxVal)?
                                                      maxVal : tmp));
                        j -= 3;
                    }
                } else {
                    for(k=db.offset+w-1, j=3*w-1+c-2; j>=0; k--) {
                        tmp = (db.data[k]>>>fracbits)+shift;
                        buf[j] = (byte)((tmp<0)? 0 : ((tmp>maxVal)?
                                                      maxVal : tmp));
                        j -= 3;
                    }
                }   
            }
            // Write buffer into file
            int psn = offset+3*(this.w*(uly+tOffy+i)+ulx+tOffx);
            buffer.position(psn);
            buffer.put(buf, 0, 3*w);
        }
    }
    
    /**
     * Writes the source's current tile to the output. The requests of data
     * issued to the source BlkImgDataSrc object are done by strips, in order
     * to reduce memory usage.
     *
     * <P>If the data returned from the BlkImgDataSrc source is progressive,
     * then it is requested over and over until it is not progressive any
     * more.
     *
     * @exception IOException If an I/O error occurs.
     * */
    public void write() throws IOException {
        int i;
        int tIdx = src.getTileIdx();
        int tw = src.getTileCompWidth(tIdx,0);  // Tile width 
        int th = src.getTileCompHeight(tIdx, 0);  // Tile height
        // Write in strips
        for(i=0; i<th ; i+=DEF_STRIP_HEIGHT) {
            write(0,i,tw,((th-i)<DEF_STRIP_HEIGHT) ? th-i : DEF_STRIP_HEIGHT);
        }
    }
    
    /**
     * Writes the header info of the PPM file :
     *
     * P6<br>
     *
     * width height<br>
     *
     * 255<br>
     *
     * @exception IOException If there is an I/O Error 
     * */
     private void writeHeaderInfo() throws IOException {
        byte[] byteVals;
        int i;
        String val;
        
        // write 'P6' to file
        buffer.position(0);
        buffer.put((byte) 80);
        buffer.put((byte) 54);
        buffer.put((byte) 10);
        offset=3;
        // Write width in ASCII
        val=String.valueOf(w);
        byteVals=val.getBytes();
        for(i=0;i<byteVals.length;i++) {
            buffer.put(byteVals[i]);
            offset++;
        }
        buffer.put((byte)32);
        offset++;
        // Write height in ASCII
        val=String.valueOf(h);
        byteVals=val.getBytes();
        for(i=0;i<byteVals.length;i++) {
            buffer.put(byteVals[i]);
            offset++;
        }
        
        buffer.put((byte)10);
        buffer.put((byte)50);
        buffer.put((byte)53);
        buffer.put((byte)53);
        buffer.put((byte)10);
        offset+=5;
     }

     public ByteArrayInputStream getByteArrayInputStream() {
         //buffer.flip();
         byte[] contents = Arrays.copyOf( buffer.array(), buffer.position());
		return new ByteArrayInputStream(contents);
     }
     
     public Bitmap getImage() throws IOException {
    	 writeAll();
         byte[] contents = Arrays.copyOf( buffer.array(), buffer.position());
    	 PPMConverter ppmc = new PPMConverter(new ByteArrayInputStream(contents));
    	 return ppmc.createBufferedImage();
     }
    /**
     * Returns a string of information about the object, more than 1 line
     * long. The information string includes information from the underlying
     * RandomAccessFile (its toString() method is called in turn).
     *
     * @return A string of information about the object.
     * */
    public String toString() {
        return "ImgWriterPPM: WxH = " + w + "x" + h + ", Components = " +
            cps[0]+","+cps[1]+","+cps[2]+ "\nUnderlying RandomAccessFile:\n";
    }
    private class PPMConverter {
    	/**
    	 * Converts a .ppm file into an android bitmap
    	 * 
    	 * @author duncan
    	 * 
    	 */

    		InputStream is;

    		private PPMConverter(InputStream is) {
    			this.is = is;
    		}

    		//public BufferedImage createBufferedImage() throws IOException {
            public Bitmap createBufferedImage() throws IOException {
    			
    			if (!readUntilWhiteSpace(is).equals("P6")) throw new IOException();
    			int width = Integer.parseInt(readUntilWhiteSpace(is));
    			int height = Integer.parseInt(readUntilWhiteSpace(is));
    			int depth = Integer.parseInt(readUntilWhiteSpace(is));
    			if (depth!=0xFF) throw new IOException("This decoder only accepts 8-bit image depth");
    			//BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
                Bitmap img = Bitmap.createBitmap(width, height,Bitmap.Config.ARGB_8888);
    			//WritableRaster raster = img.getRaster();
    			int[] pixel = new int[3];
    			// Read in the pixels
    			for (int y = 0; y < height; y++) {
    				for (int x = 0; x < width; x++) {
    					int red = is.read();
    					int green = is.read();
    					int blue = is.read();
    					if (red>255 || red<0) {
    						//Log.e(DEBUG,"Red out of range");
    						throw new IOException();
    					}
    					if (green>255 || green<0) {
    						//Log.e(DEBUG,"Green out of range");
    						throw new IOException();
    					}
    					if (blue>255 || blue<0) {
    						//Log.e(DEBUG,"Blue out of range");
    						throw new IOException();
    					}
    					pixel[0]=red;
    					pixel[1]=green;
    					pixel[2]=blue;
                        //raster.setPixel(x, y, pixel);
                        img.setPixel(x, y, getIntFromColor(pixel[0],pixel[1],pixel[2]));
    				}
    			}
    			return img;
    		}

            public int getIntFromColor(int Red, int Green, int Blue){
                Red = (Red << 16) & 0x00FF0000;     //Shift red 16-bits and mask out other stuff
                Green = (Green << 8) & 0x0000FF00;  //Shift Green 8-bits and mask out other stuff
                Blue = Blue & 0x000000FF;           //Mask out anything not blue.

                return 0xFF000000 | Red | Green | Blue; //0xFF000000 for 100% Alpha. Bitwise OR everything together.
            }


    		/**
    		 * Read characters until whitespace is encountered, then returns a string
    		 * DOES NOT CHECK FOR EOF
    		 * @return
    		 * @throws IOException 
    		 */
    		public String readUntilWhiteSpace(InputStream is) throws IOException {
    			String data="";
    			int b;
    			char next = (char) is.read();
    			//skip any whitespace
    			while(next =='\n' || next ==' ' || next=='\t') {
    				next = (char) is.read();
    			}
    			while(next !='\n' && next !=' ' && next!='\t') {
    				data += next;
    				b = is.read();
    				if (b==-1) throw new IOException("Unexpected EOF while reading header");
    				next = (char)b;
    			}	
    			return data;
    		}
    }
}
