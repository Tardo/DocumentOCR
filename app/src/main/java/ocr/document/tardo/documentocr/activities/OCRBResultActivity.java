/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;

import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.utils.Constants;
import ocr.document.tardo.documentocr.utils.OCRInfo;

public class OCRBResultActivity extends Activity implements View.OnClickListener {

    final private int VALIDATION_FAIL = -1;
    final private int VALIDATION_OK = 1;

    private Button mButtonValidate;

    private HandlerThread mBackgroundThread;
    private Handler mBackgroundHandler;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_ocrb_result);

        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            String[] name = extras.getString("NAME", "").split("\\s\\s");
            String docNumber = extras.getString("DOC_NUMBER");
            String caducity = extras.getString("CADUCITY");
            String birthday = extras.getString("BIRTHDAY");
            String gender = extras.getString("GENDER");
            String nation = extras.getString("NATION");
            String expedition = extras.getString("EXPEDITION");
            byte[] byteArray = extras.getByteArray("IMAGE_OCRB");
            BitmapFactory.Options opt = new BitmapFactory.Options();
            opt.inMutable = true;
            Bitmap imgOCR = BitmapFactory.decodeByteArray(byteArray, 0, byteArray != null ? byteArray.length : 0, opt);
            String ocrBoxes = extras.getString("OCR_TEXT_BOXES");

            TextView tvloc;

            if (name.length > 1) {
                tvloc = findViewById(R.id.CITIZEN_data_tab_01);
                tvloc.setText(name[1]);
                tvloc = findViewById(R.id.CITIZEN_data_tab_02);
                tvloc.setText(name[0]);
            }
            tvloc = findViewById(R.id.CITIZEN_data_tab_03);
            tvloc.setText(docNumber);
            tvloc = findViewById(R.id.CITIZEN_data_tab_03_caducity);
            tvloc.setText(caducity);
            tvloc = findViewById(R.id.CITIZEN_data_tab_07);
            tvloc.setText(birthday);
            tvloc = findViewById(R.id.CITIZEN_data_tab_08);
            tvloc.setText(nation);
            tvloc = findViewById(R.id.CITIZEN_data_tab_sex);
            tvloc.setText(gender);
            tvloc = findViewById(R.id.CITIZEN_data_tab_10);
            tvloc.setText(expedition);

            ImageView image = findViewById(R.id.imgOCR);
            image.setImageBitmap(imgOCR);
        }

        final Button ButtonOCRBBack = findViewById(R.id.btnBack);
        ButtonOCRBBack.setOnClickListener(this);
        mButtonValidate = findViewById(R.id.btnValidate);
        mButtonValidate.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnBack) {
            Intent intent = new Intent(OCRBResultActivity.this, ReadModeActivity.class);
            startActivity(intent);
            finish();
        } else if (v.getId() == R.id.btnValidate) {
            final Button btnValidate = (Button)v;
            btnValidate.setEnabled(false);
            btnValidate.setText(R.string.sending);
            mBackgroundHandler.post(new RPCCreatePartner(this, ((AppMain)getApplication()).OdooClient()));
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        startBackgroundThread();
    }

    @Override
    public void onPause() {
        stopBackgroundThread();
        super.onPause();
    }

    private void startBackgroundThread() {
        mBackgroundThread = new HandlerThread("RPCBackground");
        mBackgroundThread.start();
        mBackgroundHandler = new Handler(mBackgroundThread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                switch (msg.what) {
                    case VALIDATION_OK: {
                        showToast(getApplicationContext().getString(R.string.jsonrpc_partner_created));
                        Intent intent = new Intent(OCRBResultActivity.this, ReadModeActivity.class);
                        startActivity(intent);
                        finish();
                        break;
                    }
                    case VALIDATION_FAIL:
                        showToast(getApplicationContext().getString(R.string.jsonrpc_partner_error));
                        OCRBResultActivity.this.runOnUiThread(new Runnable() {
                            public void run() {
                                mButtonValidate.setText(R.string.validate);
                                mButtonValidate.setEnabled(true);
                            }
                        });
                        break;
                    default:
                        break;
                }
            }
        };
    }

    private void stopBackgroundThread() {
        mBackgroundThread.quitSafely();
        try {
            mBackgroundThread.join();
            mBackgroundThread = null;
            mBackgroundHandler = null;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void showToast(final String text) {
        final Activity activity = this;
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(activity, text, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private class RPCCreatePartner implements Runnable {

        final JSONRPCClientOdoo mClient;
        final private OCRBResultActivity ocrbResultActivity;


        RPCCreatePartner(OCRBResultActivity activity, JSONRPCClientOdoo client) {
            mClient = client;
            ocrbResultActivity = activity;
        }


        @Override
        public void run() {
            int state = VALIDATION_FAIL;
            final SharedPreferences Settings = ocrbResultActivity.getSharedPreferences(Constants.SHARED_PREFS_USER_INFO, Context.MODE_PRIVATE);
            final boolean hasHotelL10N = Settings.getBoolean("HasHotelL10N", false);
            final Bundle extras = ocrbResultActivity.getIntent().getExtras();
            if (extras == null) {
                Message completeMessage = mBackgroundHandler.obtainMessage(state, "");
                completeMessage.sendToTarget();
                return;
            }
            String name = extras.getString("NAME", "");
            String docNumber = extras.getString("DOC_NUMBER", "");
            String oexpedition = extras.getString("OEXPEDITION", "");
            String obirthday = extras.getString("OBIRTHDAY", "");
            String gender = extras.getString("GENDER", "");
            String nation = extras.getString("NATION", "");
            int docType = extras.getInt("DOC_TYPE");
            String docTypeOdoo = docType==OCRInfo.ID_TYPE_DNI?"DNI":"Passport";

            String ogender = "other";
            if ('M' == gender.charAt(0)) {
                ogender = "male";
            } else if ('F' == gender.charAt(0)) {
                ogender = "female";
            }

            try {
                String createValues;
                // Hotel L10N Support
                if (hasHotelL10N) {
                    createValues = String.format(
                            "{'name': \"%s\", 'document_number': \"%s\", 'birthdate_date': \"%s\", 'gender': \"%s\", 'document_expedition_date': \"%s\", 'document_type': \"%c\", 'comment': \"Nation: %s\"}",
                            name, docNumber, obirthday, ogender, oexpedition, docTypeOdoo.charAt(0), nation);
                } else {
                    createValues = String.format(
                            "{'name': \"%s\", 'vat': \"%s\", 'comment': \"Birthday: %s\nGender: %s\nNation: %s\nDocument Expedition Date: %s\nDocument Type: %s\"}",
                            name, docNumber, obirthday, ogender, nation, oexpedition, docTypeOdoo);
                }

                final int mOperationResult = mClient.callCreate("res.partner", createValues);

                if (mOperationResult != JSONRPCClientOdoo.ERROR) {
                    state = VALIDATION_OK;
                }
            } catch (OdooSearchException e) {
                e.printStackTrace(); // TODO: It's an error, don't hide & forget it ¬¬
            }

            Message completeMessage = mBackgroundHandler.obtainMessage(state, "");
            completeMessage.sendToTarget();
        }
    }
}
