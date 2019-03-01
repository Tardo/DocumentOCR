package ocr.document.tardo.documentocr.utils.jj2000;

import android.graphics.Bitmap;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import colorspace.ColorSpace;
import colorspace.ColorSpaceException;
import icc.ICCProfileException;
import jj2000.j2k.codestream.HeaderInfo;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.codestream.reader.HeaderDecoder;
import jj2000.j2k.decoder.Decoder;
import jj2000.j2k.decoder.DecoderSpecs;
import jj2000.j2k.entropy.decoder.EntropyDecoder;
import jj2000.j2k.image.BlkImgDataSrc;
import jj2000.j2k.image.ImgDataConverter;
import jj2000.j2k.image.invcomptransf.InvCompTransf;
import jj2000.j2k.quantization.dequantizer.Dequantizer;
import jj2000.j2k.roi.ROIDeScaler;
import jj2000.j2k.util.ISRandomAccessIO;
import jj2000.j2k.util.ParameterList;
import jj2000.j2k.wavelet.synthesis.InverseWT;

public class J2kStreamDecoder {

	public J2kStreamDecoder() {
	}

	public Bitmap decode(InputStream is) throws EOFException, IOException,
			ColorSpaceException, ICCProfileException {
		ISRandomAccessIO in = new ISRandomAccessIO(is);
		ParameterList defpl = new ParameterList();
		String[][] param = Decoder.getAllParameters();

		for (int i = param.length - 1; i >= 0; i--) {
			if (param[i][3] != null)
				defpl.put(param[i][0], param[i][3]);
		}
		// Create parameter list using defaults
		ParameterList pl = new ParameterList(defpl);

		// **** File Format ****
		// If the codestream is wrapped in the jp2 fileformat, Read the
		// file format wrapper
		MyFileFormatReader ff = new MyFileFormatReader(in);
		ff.readFileFormat();
		if (ff.JP2FFUsed) {
			in.seek(ff.getFirstCodeStreamPos());
		}

		// **** header decoder ****
		HeaderInfo hi = new HeaderInfo();
		HeaderDecoder hd = null;
		DecoderSpecs decSpec = null;
		hd = new HeaderDecoder(in, pl, hi);
		decSpec = hd.getDecoderSpecs();
		// Get demixed bitdepths
		int nCompCod = hd.getNumComps();
		int[] depth = new int[nCompCod];
		for (int i = 0; i < nCompCod; i++) {
			depth[i] = hd.getOriginalBitDepth(i);
		}

		// **** Bit stream reader ****
		BitstreamReaderAgent breader = BitstreamReaderAgent.createInstance(in,
				hd, pl, decSpec, pl.getBooleanParameter("cdstr_info"), hi);

		// **** Entropy decoder ****
		EntropyDecoder entdec = hd.createEntropyDecoder(breader, pl);

		// **** ROI de-scaler ****
		ROIDeScaler roids = hd.createROIDeScaler(entdec, pl, decSpec);

		// **** Dequantizer ****
		Dequantizer deq = hd.createDequantizer(roids, depth, decSpec);

		// full page inverse wavelet transform
		InverseWT invWT = InverseWT.createInstance(deq, decSpec);
		int res = breader.getImgRes();
		invWT.setImgResLevel(res);

		// **** Data converter **** (after inverse transform module)
		ImgDataConverter converter = new ImgDataConverter(invWT, 0);

		// **** Inverse component transformation ****
		InvCompTransf ictransf = new InvCompTransf(converter, decSpec, depth,
				pl);

		// **** Color space mapping ****
		ColorSpace csMap;
		BlkImgDataSrc color = null;
		BlkImgDataSrc palettized;
		BlkImgDataSrc resampled;
		BlkImgDataSrc channels;
		if (ff.JP2FFUsed && pl.getParameter("nocolorspace").equals("off")) {
			csMap = new ColorSpace(in, hd, pl);
			channels = hd.createChannelDefinitionMapper(ictransf, csMap);
			resampled = hd.createResampler(channels, csMap);
			palettized = hd.createPalettizedColorSpaceMapper(resampled, csMap);
			color = hd.createColorSpaceMapper(palettized, csMap);
		} else { // Skip colorspace mapping
			color = ictransf;
		}
		// This is the last image in the decoding chain
		BlkImgDataSrc decodedImage = color;
		if (color == null) {
			decodedImage = ictransf;
		}
		// write out the image
		ImgStreamWriter imwriter = new ImgStreamWriter(decodedImage, 0, 1, 2);
		return imwriter.getImage();
	}
}
