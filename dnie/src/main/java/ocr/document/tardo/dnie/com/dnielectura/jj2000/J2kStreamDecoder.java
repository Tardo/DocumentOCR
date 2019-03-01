package com.dnielectura.jj2000;

import android.graphics.Bitmap;
import colorspace.ColorSpace;
import colorspace.ColorSpaceException;
import icc.ICCProfileException;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.codestream.reader.HeaderDecoder;
import jj2000.j2k.decoder.Decoder;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.ImgDataConverter;
import jj2000.j2k.image.invcomptransf.InvCompTransf;
import jj2000.j2k.util.ISRandomAccessIO;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.InverseWT;

public class J2kStreamDecoder {
    public Bitmap decode(InputStream is) throws EOFException, IOException, ColorSpaceException, ICCProfileException {
        int i;
        BlkImgDataSrc color;
        ISRandomAccessIO in = new ISRandomAccessIO(is);
        ParameterList defpl = new ParameterList();
        String[][] param = Decoder.getAllParameters();
        for (i = param.length - 1; i >= 0; i--) {
            if (param[i][3] != null) {
                defpl.put(param[i][0], param[i][3]);
            }
        }
        ParameterList pl = new ParameterList(defpl);
        MyFileFormatReader myFileFormatReader = new MyFileFormatReader(in);
        myFileFormatReader.readFileFormat();
        if (myFileFormatReader.JP2FFUsed) {
            in.seek(myFileFormatReader.getFirstCodeStreamPos());
        }
        HeaderInfo hi = new HeaderInfo();
        HeaderDecoder hd = new HeaderDecoder(in, pl, hi);
        DecoderSpecs decSpec = hd.getDecoderSpecs();
        int nCompCod = hd.getNumComps();
        int[] depth = new int[nCompCod];
        for (i = 0; i < nCompCod; i++) {
            depth[i] = hd.getOriginalBitDepth(i);
        }
        BitstreamReaderAgent breader = BitstreamReaderAgent.createInstance(in, hd, pl, decSpec, pl.getBooleanParameter("cdstr_info"), hi);
        InverseWT invWT = InverseWT.createInstance(hd.createDequantizer(hd.createROIDeScaler(hd.createEntropyDecoder(breader, pl), pl, decSpec), depth, decSpec), decSpec);
        invWT.setImgResLevel(breader.getImgRes());
        InvCompTransf invCompTransf = new InvCompTransf(new ImgDataConverter(invWT, 0), decSpec, depth, pl);
        if (myFileFormatReader.JP2FFUsed && pl.getParameter("nocolorspace").equals("off")) {
            ColorSpace csMap = new ColorSpace(in, hd, pl);
            color = hd.createColorSpaceMapper(hd.createPalettizedColorSpaceMapper(hd.createResampler(hd.createChannelDefinitionMapper(invCompTransf, csMap), csMap), csMap), csMap);
        } else {
            Object color2 = invCompTransf;
        }
        BlkImgDataSrc decodedImage = color;
        if (color == null) {
            decodedImage = invCompTransf;
        }
        return new ImgStreamWriter(decodedImage, 0, 1, 2).getImage();
    }
}
