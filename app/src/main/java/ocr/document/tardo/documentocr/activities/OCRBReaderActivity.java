/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import ocr.document.tardo.documentocr.fragments.OCRBReaderFragment;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.utils.OCRInfo;
import ocr.document.tardo.documentocr.utils.DateHelper;

public class OCRBReaderActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ocrb_reader);
        if (null == savedInstanceState) {
            getSupportFragmentManager().beginTransaction()
                    .replace(R.id.container, OCRBReaderFragment.newInstance())
                    .commit();
        }
    }

    public void printOCRResults(OCRInfo ocrInfo, Bitmap imgOCR, String boxes) {
        DateFormat df = DateFormat.getDateInstance(2);
        DateFormat odf = new SimpleDateFormat("YYYY-MM-dd");

        Bundle bundle = new Bundle();
        bundle.putString("NAME", ocrInfo.mName);
        bundle.putString("DOC_NUMBER", ocrInfo.mDNI);
        bundle.putString("GENDER", ocrInfo.mGender);
        bundle.putString("BIRTHDAY", (null != ocrInfo.mBirthdayDate ? df.format(ocrInfo.mBirthdayDate) : ""));
        bundle.putString("OBIRTHDAY", (null != ocrInfo.mBirthdayDate ? odf.format(ocrInfo.mBirthdayDate) : ""));
        bundle.putString("NATION", ocrInfo.mCountry);
        bundle.putString("CARD_SERIAL", ocrInfo.mCardNumber);
        bundle.putString("CADUCITY", (null != ocrInfo.mEndDate ? df.format(ocrInfo.mEndDate) : ""));

        Date dnieTest = DateHelper.getExpeditionDate(ocrInfo.mBirthdayDate, ocrInfo.mEndDate);
        if (null != dnieTest) {
            bundle.putString("EXPEDITION", df.format(dnieTest));
            bundle.putString("OEXPEDITION", odf.format(dnieTest));
        } else {
            bundle.putString("EXPEDITION", getApplicationContext().getString(R.string.info_expiry_permanent));
            bundle.putString("OEXPEDITION", "0");
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        imgOCR.compress(Bitmap.CompressFormat.PNG, 100, stream);
        byte[] byteArray = stream.toByteArray();
        bundle.putByteArray("IMAGE_OCRB", byteArray);

        bundle.putString("OCR_TEXT_BOXES", boxes);

        Intent myResultIntent = new Intent(OCRBReaderActivity.this, OCRBResultActivity.class);
        myResultIntent.putExtras(bundle);
        startActivity(myResultIntent);
        finish();
    };

}