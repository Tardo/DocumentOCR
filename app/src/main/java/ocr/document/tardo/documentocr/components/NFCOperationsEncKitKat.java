package ocr.document.tardo.documentocr.components;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import java.security.KeyStoreSpi;
import java.security.Security;

import de.tsenger.androsmex.data.CANSpecDO;
import de.tsenger.androsmex.data.CANSpecDOStore;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import de.tsenger.androsmex.pace.PaceException;
import es.gob.jmulticard.jse.provider.DnieKeyStore;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl;
import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.activities.DNIeErrorActivity;
import ocr.document.tardo.documentocr.activities.DNIeResultActivity;
import ocr.document.tardo.documentocr.activities.ReadModeActivity;

@SuppressLint("NewApi")
public class NFCOperationsEncKitKat extends Activity implements ReaderCallback {
	// NFC Adapter
    static private NfcAdapter mNfcAdapter = null;

    // CAN Management
    private CANSpecDO mCANDnie;
    private CANSpecDOStore mCANDOS;
    private Activity mActivity;

    // Variables member of files available in the document
    private boolean mExistDG1;
    private boolean mExistDG2;
    private boolean mExistDG7;
    private boolean mExistDG11;

    private DG1_Dnie mDG1;
    private DG11 mDG11;
    private DG2 mDG2;
    private DG7 mDG7;

    private boolean mReaderModeON = false;

    private DnieKeyStore mKSUserMrtd = null;

    final Handler mHandler = new Handler();
    private ProgressDialog mProgressBar;

	private Tag mTagFromIntent =null;

    Typeface mFontType;
    private String mTextProcessDlg;
    private String mTextResultPage;

    private boolean mForceReset = true;

    final Runnable updateStatus = new Runnable() {
        public void run()
        {
            mProgressBar.setMessage(mTextProcessDlg);
            if(!mProgressBar.isShowing())
                mProgressBar.show();
        }
    };

    final Runnable askForRead = new Runnable()
    {
        public void run()
        {
            mTextResultPage ="";
            mTextResultPage ="";
            ((TextView)findViewById(R.id.textResult)).setText(R.string.op_reinit);
            findViewById(R.id.textResult).setVisibility(TextView.VISIBLE);
            ((ImageView)findViewById(R.id.imgResult)).setImageResource(R.drawable.btn_aproxdnie);
            findViewById(R.id.imgResult).setVisibility(ImageView.VISIBLE);
            findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);
        }
    };

    final Runnable newRead = new Runnable()
    {
        public void run()
        {
            mTextResultPage ="";
            mTextResultPage ="";
            ((TextView)findViewById(R.id.textResult)).setText(R.string.process_msg_lectura);
            findViewById(R.id.textResult).setVisibility(TextView.VISIBLE);
            ((ImageView)findViewById(R.id.imgResult)).setImageResource(R.drawable.btn_aproxdnie);
            findViewById(R.id.imgResult).setVisibility(ImageView.VISIBLE);
            findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);
        }
    };

    public void HandleError(String strError) {
        Bundle b = new Bundle();
        b.putString("ERROR_MSG", strError);

        Intent myResultIntent = new Intent(NFCOperationsEncKitKat.this, DNIeErrorActivity.class);
        myResultIntent.putExtras(b);
        startActivity(myResultIntent);
    }

    public class MyTaskDG11 extends AsyncTask<Void, Integer, Void> {

        private boolean mHasErrors = false;

        @Override
        protected void onPreExecute() {
            // Clean Controls
            mHandler.post(newRead);

            // Prepare auto-reset for possible reading failure
            mForceReset = true;

            // Show Dialog Process
            mProgressBar.setIndeterminate(true);
            mProgressBar.setCancelable(false);
            mProgressBar.setTitle(R.string.process_title);
            mProgressBar.setMessage(getApplicationContext().getString(R.string.process_msg_dni));
            mTextProcessDlg = getApplicationContext().getString(R.string.process_msg_dni);
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            // TODO Auto-generated method stub
            super.onProgressUpdate(values);

            mProgressBar.setMessage(mTextProcessDlg);
            if(!mProgressBar.isShowing())
                mProgressBar.show();
        }

        @Override
        protected Void doInBackground(Void... params) {

            try {
                // Start NFC Read Operation
                LoadDGs();

                mForceReset = false;
            }
            catch (PaceException e) {
                // Invalid CAN
                mTextResultPage = e.getMessage();
                mForceReset = false;
                mHasErrors = true;

                return null;
            }
            catch (Exception e) {
                mTextResultPage = getApplicationContext().getString(R.string.nfc_error_read);
                if (e.getMessage()!=null) {
                    if (e.getMessage().contains("lost"))
                        mTextResultPage = getApplicationContext().getString(R.string.nfc_error_lost);
                    else
                        mTextResultPage = e.getMessage();
                }
                return null;
            }

            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
            mProgressBar.dismiss();

            mKSUserMrtd = null;

            // Read again NFC Card... perhaps moved.
            if (mForceReset) {
                mHandler.post(askForRead);

                // Check NFC Card with a delay of ~250ms
                mReaderModeON = EnableReaderMode(250);
                return;
            }

            if (mHasErrors)
                HandleError(mTextResultPage);
            else {
                Bundle b = new Bundle();
                if (mDG1 != null) b.putByteArray("DGP_DG1", mDG1.getBytes());
                if (mDG2 != null) b.putByteArray("DGP_DG2", mDG2.getBytes());
                if (mDG7 != null) b.putByteArray("DGP_DG7", mDG7.getBytes());
                if (mDG11 != null) b.putByteArray("DGP_DG11", mDG11.getBytes());

                Intent myResultIntent = new Intent(NFCOperationsEncKitKat.this, DNIeResultActivity.class);
                myResultIntent.putExtras(b);
                startActivityForResult(myResultIntent, 1);
            }
        }
    }

    @Override
    public void onCreate(Bundle savedState) {
        super.onCreate(savedState);

        // Remove titlebar
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.component_dnie_read_kitkat);

        mTagFromIntent = null;

        Context myContext = NFCOperationsEncKitKat.this;
        mActivity = ((Activity) myContext);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mNfcAdapter.setNdefPushMessage(null, this);
        mNfcAdapter.setNdefPushMessageCallback(null, this);

        mDG1 = null;
        mDG2 = null;
        mDG7 = null;
        mDG11 = null;

        mProgressBar = new ProgressDialog(myContext);

        findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);

        mCANDOS = new CANSpecDOStore(this);
        mCANDnie = ((AppMain)getApplicationContext()).getCAN();

        TextView myText = findViewById(R.id.infoResult);
        myText.setVisibility(TextView.INVISIBLE);
        myText.setTypeface(mFontType);

    	Button btnNFCBack = findViewById(R.id.btnBack);
    	btnNFCBack.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
                onBackPressed();
			}
		});
    }

    @Override
    public void onResume() {
        super.onResume();
        if (!mReaderModeON)
            mReaderModeON = EnableReaderMode(1000);
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if ((keyCode == KeyEvent.KEYCODE_BACK)) {
			Intent intent = new Intent(NFCOperationsEncKitKat.this, ReadModeActivity.class);
	        startActivity(intent);
	        return false;
        }
        else
        	return super.onKeyDown(keyCode, event);
    }

    private boolean EnableReaderMode (int msDelay)
    {
        Bundle options = new Bundle();
        options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, msDelay);
        mNfcAdapter.enableReaderMode(mActivity,
                this,
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
                        NfcAdapter.FLAG_READER_NFC_B,
                options);
        return true;
    }

    private boolean DisableReaderMode()
    {
        mNfcAdapter.disableReaderMode(this);
        mReaderModeON = false;
        return true;
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        try {
            mTagFromIntent = tag;

            MyTaskDG11 newTask = new MyTaskDG11();
            newTask.execute();

        } catch (Exception e)
        {
            mTextResultPage = getApplicationContext().getString(R.string.nfc_error_files) + "\n" + e.getMessage();
        }
    }

    public boolean LoadDGs() throws PaceException, Exception
    {
        try
        {
            // Read DG1 & DG11 data
            mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading);
            mHandler.post(updateStatus);

            // Enable fast-mode
            System.setProperty("es.gob.jmulticard.fastmode", "true");

            // Load DNie services provider
            final DnieProvider p = new DnieProvider();
            p.setProviderTag(mTagFromIntent);
            String can6digitos = mCANDnie.getCanNumber();
            while (can6digitos.length() < 6)
                can6digitos = "0"+can6digitos;
            p.setProviderCan(can6digitos);
            Security.insertProviderAt(p, 1);

            // Create DNIe Key Store
            KeyStoreSpi ksSpi = new MrtdKeyStoreImpl();
            mKSUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");
            mKSUserMrtd.load(null, null);

            // Read EF_COM to know available data on the document
            try{
                EF_COM m_efcom = mKSUserMrtd.getEFCOM();
                byte[] tagList = m_efcom.getTagList();

                for(int idx=0;idx<tagList.length;idx++) {
                    switch (tagList[idx]) {
                        case 0x61:
                            // DG_1
                            mExistDG1 = true;
                            break;
                        case 0x75:
                            // DG_2
                            mExistDG2 = true;
                            break;
                        case 0x67:
                            // DG_7
                            mExistDG7 = true;
                            break;
                        case 0x6B:
                            // DG_11
                            mExistDG11 = true;
                            break;
                    }
                }
            } catch (Exception e)
            {
                e.printStackTrace();
                throw e;
            }

            // Read available DG's
            if (mExistDG1) {
                try {
                    mDG1 = mKSUserMrtd.getDatagroup1();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (mExistDG11) {
                try {
                    mDG11 = mKSUserMrtd.getDatagroup11();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            // Update CAN DO
            if (mCANDnie.getUserNif().length() == 0)
            {
                String docNumber;
                String certSubject = mDG1.getName() + " " + mDG1.getSurname();
                if (mDG11 == null)
                    docNumber = mDG1.getDocNumber();
                else
                    docNumber = mDG11.getPersonalNumber();
                CANSpecDO newCan = new CANSpecDO(mCANDnie.getCanNumber(), certSubject, docNumber);
                mCANDOS.delete(mCANDnie);
                mCANDOS.save(newCan);
            }

            if (mExistDG2)
            {
                try {
                    mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading_photo);
                    mHandler.post(updateStatus);

                    mDG2 = mKSUserMrtd.getDatagroup2();

                } catch (Exception e)
                {
                    e.printStackTrace();
                    throw e;
                }
            }

            if (mExistDG7)
            {
                try {
                    mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading_signature);
                    mHandler.post(updateStatus);

                    mDG7 = mKSUserMrtd.getDatagroup7();
                } catch (Exception e)
                {
                    e.printStackTrace();
                    throw e;
                }
            }
        }
        catch(Exception e)
        {
            mTextResultPage = getApplicationContext().getString(R.string.nfc_error_read) + "\n";
            if(e.getMessage() != null) {
                if (e.getMessage().contains("CAN incorrecto")) {
                    mTextResultPage = getApplicationContext().getString(R.string.nfc_error_CAN);
                    throw new PaceException(mTextResultPage);
                }

                if (e.getMessage().contains("Tag was lost")) {
                    mTextResultPage += getApplicationContext().getString(R.string.nfc_error_lost);
                    throw new Exception(mTextResultPage);
                }

                mTextResultPage += e.getMessage();
            }

            throw new Exception(mTextResultPage);
        }

        return true;
    }

}
