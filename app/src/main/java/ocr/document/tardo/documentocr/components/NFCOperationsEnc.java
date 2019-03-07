package ocr.document.tardo.documentocr.components;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcB;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

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
import ocr.document.tardo.documentocr.activities.DNIeCANActivity;
import ocr.document.tardo.documentocr.activities.DNIeErrorActivity;
import ocr.document.tardo.documentocr.activities.DNIeResultActivity;


public class NFCOperationsEnc extends Activity {
	private NfcA mExNfcA;
	private NfcB mExNfcB;
	private IsoDep mExIsoDep;

	private Tag mTagFromIntent = null;
	private boolean mRestart = false;

	private ProgressDialog mProgressDlg;
	final Handler mHandler = new Handler();

	// Variables member of files available in the document
	private boolean mExistDG1;
	private boolean mExistDG2;
	private boolean mExistDG7;
	private boolean mExistDG11;

	private EF_COM mEFCom;
	private DG1_Dnie mDG1;
	private DG11 mDG11;
	private DG2 mDG2;
	private DG7 mDG7;

	private String mTextProcessDlg;
	private String mTextResultPage;

	final Runnable updateStatus = new Runnable() {
		public void run() {
			mProgressDlg.setMessage(mTextProcessDlg);
		}
	};

	final Runnable cleanFragment = new Runnable() {
		public void run()
		{
			mTextResultPage ="";
			mTextResultPage ="";
			((TextView)findViewById(R.id.result1)).setText(R.string.process_msg_lectura);
			findViewById(R.id.result1).setVisibility(TextView.VISIBLE);
			((ImageView)findViewById(R.id.imgResult)).setImageResource(R.drawable.btn_aproxdnie);
			findViewById(R.id.imgResult).setVisibility(ImageView.VISIBLE);
			findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);
		}
	};

	public class MyTaskDNIe extends AsyncTask<Void, Integer, Void> {
		private boolean mCompleted = false;

		@Override
		protected void onPreExecute() {
			mCompleted = false;

			// Clean Controls
			mHandler.post(cleanFragment);

			// Show Dialog Process
			mProgressDlg.setIndeterminate(true);
			mProgressDlg.setCancelable(false);
			mProgressDlg.setTitle(R.string.process_title);
			mProgressDlg.setMessage(getApplicationContext().getString(R.string.process_msg_dni));
			mProgressDlg.show();
		}

		@Override
		protected Void doInBackground(Void... arg0) {
			try {
				// Start NFC Read Operation
				CargarDGs();

				mCompleted = true;
			} catch (PaceException e) {
				// Invalid CAN
				mTextResultPage = e.getMessage();
				return null;
			} catch (Exception e) {
				mTextResultPage = getApplicationContext().getString(R.string.nfc_error_read);

				if (e.getMessage() != null) {
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
			if (!mCompleted) {
				mProgressDlg.dismiss();
				HandleError(mTextResultPage);

				return;
			}

			mRestart = false;

			Bundle b = new Bundle();
			if (mDG1 !=null) b.putByteArray("DGP_DG1", mDG1.getBytes());
			if (mDG11 !=null) b.putByteArray("DGP_DG11", mDG11.getBytes());
			if (mDG2 !=null) b.putByteArray("DGP_DG2", mDG2.getBytes());
			if (mDG7 !=null) b.putByteArray("DGP_DG7", mDG7.getBytes());

			Intent myResultIntent = new Intent(NFCOperationsEnc.this, DNIeResultActivity.class);
			myResultIntent.putExtras(b);
			startActivity(myResultIntent);
		}
	}

	@Override
	public void onCreate(Bundle savedState) {
		super.onCreate(savedState);

		// If not open properly, close.
		if (!((AppMain) getApplicationContext()).isStarted()) {
			Toast.makeText(getApplicationContext(), getApplicationContext().getString(R.string.activity_error_open), Toast.LENGTH_LONG).show();

			PackageManager packman = getApplicationContext().getPackageManager();
			ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
			packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0);//*/

			android.os.Process.killProcess(android.os.Process.myPid());
			System.exit(0);

			return;
		}

		this.requestWindowFeature(Window.FEATURE_NO_TITLE);
		setContentView(R.layout.component_dnie_read);

		mTagFromIntent = null;
		mProgressDlg = new ProgressDialog(NFCOperationsEnc.this);

		Intent intent = getIntent();
		resolveIntent(intent);

		if (mTagFromIntent == null) {
			return;
		}

		// Interface NfcA or NfcB
		if ((mExNfcA != null || mExNfcB != null) && mExIsoDep != null)  {
            mExIsoDep.setTimeout(3000);

            MyTaskDNIe newTask = new MyTaskDNIe();
            newTask.execute();
		}


		Button btnNFCBack = (Button) findViewById(R.id.btnBack);
		btnNFCBack.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				Intent intent = new Intent(NFCOperationsEnc.this, DNIeCANActivity.class);
				startActivity(intent);
			}
		});

	}

	@Override
	protected void onStart() {
		// TODO Auto-generated method stub
		super.onStart();

		PackageManager packman = getApplicationContext().getPackageManager();
		ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
		packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);//*/

		if (mRestart) {
            // If not open properly, close.
			if (!((AppMain) getApplicationContext()).isStarted()) {
				Toast.makeText(getApplicationContext(), getApplicationContext().getString(R.string.activity_error_open), Toast.LENGTH_SHORT).show();
				android.os.Process.killProcess(android.os.Process.myPid());
				System.exit(0);
				return;
			}

			if (mTagFromIntent == null) {
				return;
			}

			// Interface NfcA or NfcB
			if ((mExNfcA != null || mExNfcB != null) && mExIsoDep != null) {
                mExIsoDep.setTimeout(3000);

                MyTaskDNIe newTask = new MyTaskDNIe();
                newTask.execute();
            }
		}
	}

	@Override
	protected void onStop() {
		// TODO Auto-generated method stub
		super.onStop();

		PackageManager packman = getApplicationContext().getPackageManager();
		ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
		packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
	}

	void resolveIntent(Intent intent) {
		mTagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		if (mTagFromIntent != null) {
			// Get available technologies
			mExNfcA = NfcA.get(mTagFromIntent);
			mExNfcB = NfcB.get(mTagFromIntent);
			mExIsoDep = IsoDep.get(mTagFromIntent);
		}
	}

	@Override
	public void onNewIntent(Intent intent) {
		setIntent(intent);
		resolveIntent(intent);

		mRestart = true;
	}

	private void HandleError(String strError) {
		Bundle b = new Bundle();
		b.putString("ERROR_MSG", strError);

		Intent myResultIntent = new Intent(NFCOperationsEnc.this, DNIeErrorActivity.class);
		myResultIntent.putExtras(b);
		startActivity(myResultIntent);
	}

	public boolean CargarDGs() throws Exception
	{
		try
		{
            // Read DG1 & DG11 data
			mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading);
			mHandler.post(updateStatus);

			CANSpecDOStore cansDO = new CANSpecDOStore(this);
			CANSpecDO canDnie = ((AppMain) getApplicationContext()).getCAN();

            // Enable fast-mode
			System.setProperty("es.gob.jmulticard.fastmode", "true");

            // Load DNie services provider
			final DnieProvider p = new DnieProvider();
			p.setProviderTag(mTagFromIntent);
			String can6digitos = canDnie.getCanNumber();
			while(can6digitos.length()<6)
				can6digitos = "0"+can6digitos;
			p.setProviderCan(can6digitos);
			Security.insertProviderAt(p, 1);

            // Create DNIe Key Store
			KeyStoreSpi ksSpi = new MrtdKeyStoreImpl();
			DnieKeyStore m_ksUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");
			m_ksUserMrtd.load(null, null);

            // Read EF_COM to know available data on the document
			try{
				mEFCom = m_ksUserMrtd.getEFCOM();

				byte[] tagList = mEFCom.getTagList();

				for (int idx=0; idx<tagList.length; idx++) {
					switch (tagList[idx]) {
						case 0x61:
							mExistDG1 = true;
							break;
						case 0x75:
							mExistDG2 = true;
							break;
						case 0x67:
							mExistDG7 = true;
							break;
						case 0x6B:
							mExistDG11 = true;
							break;
					}
				}

			}catch (Exception e)
			{
				e.printStackTrace();
				throw e;
			}


            if (mExistDG1) {
                try {
                    mDG1 = m_ksUserMrtd.getDatagroup1();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

			if (mExistDG11) {
                try {
                    if (mExistDG11)
                        mDG11 = m_ksUserMrtd.getDatagroup11();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            // Update CAN DO
			if (canDnie.getUserNif().length() == 0) {
				String docNumber;
				String certSubject = mDG1.getName() + " " + mDG1.getSurname();
				if (mDG11 == null)
					docNumber = mDG1.getDocNumber();
				else
					docNumber = mDG11.getPersonalNumber();
				CANSpecDO newCan = new CANSpecDO(canDnie.getCanNumber(), certSubject, docNumber);
				cansDO.delete(canDnie);
				cansDO.save(newCan);
			}

			if (mExistDG2) {
				try {
					mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading_photo);
					mHandler.post(updateStatus);

					mDG2 = m_ksUserMrtd.getDatagroup2();

				} catch (Exception e) {
					e.printStackTrace();
					throw e;
				}
			}

			if (mExistDG7) {
				try {
					mTextProcessDlg = getApplicationContext().getString(R.string.nfc_reading_signature);
					mHandler.post(updateStatus);

					mDG7 = m_ksUserMrtd.getDatagroup7();
				} catch (Exception e) {
					e.printStackTrace();
					throw e;
				}
			}
		} catch(Exception e) {
			mTextResultPage = getApplicationContext().getString(R.string.nfc_error_read) + "\n";
			if (e.getMessage()!=null) {
				if (e.getMessage().contains("Tag was lost"))
					mTextResultPage += getApplicationContext().getString(R.string.nfc_error_lost);
				else
					mTextResultPage += e.getMessage();
			}
			throw new Exception(mTextResultPage);
		}
		return true;
	}

}
