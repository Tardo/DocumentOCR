/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import ocr.document.tardo.documentocr.fragments.OCRBReaderFragment;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.fragments.OCRTask;
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

    public void printOCRResults(OCRTask ocrTask) {
        DateFormat df = DateFormat.getDateInstance(2);
        DateFormat odf = new SimpleDateFormat("YYYY-MM-dd");

        Bundle bundle = new Bundle();
        bundle.putString("NAME", ocrTask.mName);
        bundle.putString("DOC_NUMBER", ocrTask.mDNI);
        bundle.putString("SEX", ocrTask.mSex);
        bundle.putString("BIRTHDAY", (null != ocrTask.mBirthdayDate ? df.format(ocrTask.mBirthdayDate) : ""));
        bundle.putString("OBIRTHDAY", (null != ocrTask.mBirthdayDate ? odf.format(ocrTask.mBirthdayDate) : ""));
        bundle.putString("NATION", ocrTask.mNation);
        bundle.putString("CARD_SERIAL", ocrTask.mCardNumber);
        bundle.putString("CADUCITY", (null != ocrTask.mEndDate ? df.format(ocrTask.mEndDate) : ""));

        Date dnieTest = DateHelper.getExpeditionDate(ocrTask.mBirthdayDate, ocrTask.mEndDate);
        if (null != dnieTest) {
            bundle.putString("EXPEDITION", df.format(dnieTest));
            bundle.putString("OEXPEDITION", odf.format(dnieTest));
        } else {
            bundle.putString("EXPEDITION", "Permanent (>=70 Years)");
            bundle.putString("OEXPEDITION", "0");
        }

        // Pasamos los datos a la activity correspondiente
        Intent myResultIntent = new Intent(OCRBReaderActivity.this, OCRBResultActivity.class);
        myResultIntent.putExtras(bundle);
        startActivity(myResultIntent);
        finish();
    };

}