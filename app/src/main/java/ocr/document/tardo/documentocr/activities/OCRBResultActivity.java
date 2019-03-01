/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;

import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;

public class OCRBResultActivity extends Activity implements View.OnClickListener {

    private Button mButtonOCRBBack;
    private Button mButtonStartRead;

    private HandlerThread mBackgroundThread;
    private Handler mBackgroundHandler;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_ocrb_result);

        Bundle extras = getIntent().getExtras();
        if (extras != null) {
            String[] name = extras.getString("NAME").split("  ");
            String docNumber = extras.getString("DOC_NUMBER");
            String caducity = extras.getString("CADUCITY");
            String birthday = extras.getString("BIRTHDAY");
            String sex = extras.getString("SEX");
            String nation = extras.getString("NATION");
            String expedition = extras.getString("EXPEDITION");

            TextView tvloc;

            tvloc = findViewById(R.id.CITIZEN_data_tab_01);
            tvloc.setText(name[1]);

            tvloc = findViewById(R.id.CITIZEN_data_tab_02);
            tvloc.setText(name[0]);
            tvloc = findViewById(R.id.CITIZEN_data_tab_03);
            tvloc.setText(docNumber);
            tvloc = findViewById(R.id.CITIZEN_data_tab_03_caducity);
            tvloc.setText(caducity);
            tvloc = findViewById(R.id.CITIZEN_data_tab_07);
            tvloc.setText(birthday);
            tvloc = findViewById(R.id.CITIZEN_data_tab_08);
            tvloc.setText(nation);
            tvloc = findViewById(R.id.CITIZEN_data_tab_sex);
            tvloc.setText(sex);
            tvloc = findViewById(R.id.CITIZEN_data_tab_10);
            tvloc.setText(expedition);
        }

        mButtonOCRBBack = findViewById(R.id.btnBack);
        mButtonStartRead = findViewById(R.id.btnValidate);

        mButtonOCRBBack.setOnClickListener(this);
        mButtonStartRead.setOnClickListener(this);
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
            btnValidate.setText("Sending...");
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
        mBackgroundHandler = new Handler(mBackgroundThread.getLooper());
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
        if (activity != null) {
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(activity, text, Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private static class RPCCreatePartner implements Runnable {

        final JSONRPCClientOdoo mClient;
        final private OCRBResultActivity mActivity;
        private int mOperationResult;


        RPCCreatePartner(OCRBResultActivity activity, JSONRPCClientOdoo client) {
            mClient = client;
            mActivity = activity;
        }


        @Override
        public void run() {
            Bundle extras = mActivity.getIntent().getExtras();
            String name = extras.getString("NAME");
            String docNumber = extras.getString("DOC_NUMBER");
            String oexpedition = extras.getString("OEXPEDITION");
            String obirthday = extras.getString("OBIRTHDAY");
            String sex = extras.getString("SEX");
            String nation = extras.getString("NATION");

            String osex = "other";
            if ('M' == sex.charAt(0)) {
                osex = "male";
            } else if ('F' == sex.charAt(0)) {
                osex = "female";
            }

            try {
                mOperationResult = mClient.callCreate(
                    "res.partner",
                        String.format("{'name': '%s', 'document_number': '%s', 'birthdate_date': '%s', 'gender': '%s', 'document_expedition_date': '%s', comment: 'Nation: %s'}", name, docNumber, obirthday, osex, oexpedition, nation)
                );

                if (mOperationResult != JSONRPCClientOdoo.ERROR) {
                    mActivity.showToast("Partner Successfully Created!");
                    Intent intent = new Intent(mActivity, ReadModeActivity.class);
                    mActivity.startActivity(intent);
                    mActivity.finish();
                } else {
                    mActivity.showToast("Error! Can't create new partner :/ Please, try again.");
                    final Button btnValidate = mActivity.findViewById(R.id.btnValidate);
                    btnValidate.setText(R.string.validate);
                    btnValidate.setEnabled(true);
                }
            } catch (OdooSearchException e) {
                // Do Nothing
            }
        }
    }
}
