package ocr.document.tardo.documentocr.activities;

import android.animation.PropertyValuesHolder;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.MediaPlayer;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.support.v4.app.ActivityOptionsCompat;
import android.support.v4.content.ContextCompat;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
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
import ocr.document.tardo.documentocr.utils.jj2000.J2kStreamDecoder;


public class DNIeReaderActivity extends Activity implements ReaderCallback {

	final private int MODE_WAITING = 1;
	final private int MODE_READING = 2;
	final private int MODE_COMPLETE = 3;
	final private int MODE_ERROR = 4;

	private static final int VIBRATE_TIME_MS = 500;

	// NFC Adapter
	static private NfcAdapter mNfcAdapter = null;

	// CAN Management
	private CANSpecDO mCANDnie;
	private CANSpecDOStore mCANDOS;

	// Variables member of files available in the document
	private boolean mExistsDG1;
	private boolean mExistsDG2;
	private boolean mExistsDG7;
	private boolean mExistsDG11;

	private DG1_Dnie mDG1;
	private DG11 mDG11;
	private DG2 mDG2;
	private DG7 mDG7;

	private boolean mReaderModeON = false;
	private boolean mDocumentReaded = false;

	private DnieKeyStore mKSUserMrtd = null;

	final Handler mHandler = new Handler();

	private Tag mTagFromIntent = null;

	private ImageView mAnimInfo;
	private TextView mAnimInfoText;

	Typeface mFontType;
	private String mTextProcess;
	private String mTextResultPage;

	private boolean mForceReset = true;

	private ValueAnimator mValueAnimatorBall1;
	private ValueAnimator mValueAnimatorBall2;
	private ValueAnimator mValueAnimatorBall3;
	private ImageView mAnimDNIeBall1;
	private ImageView mAnimDNIeBall2;
	private ImageView mAnimDNIeBall3;

	private MediaPlayer mSoundError;
	private MediaPlayer mSoundSuccess;

	final Runnable updateStatus = new Runnable() {
		public void run()
		{
			mAnimInfoText.setText(mTextProcess);
		}
	};

	final Runnable askForRead = new Runnable()
	{
		public void run()
		{
			mTextResultPage = "";
			setMode(MODE_ERROR);
		}
	};

	final Runnable newRead = new Runnable()
	{
		public void run()
		{
			mTextResultPage = "";
			setMode(MODE_READING);
		}
	};

	public void HandleError(String strError) {
		Bundle b = new Bundle();
		b.putString("ERROR_MSG", strError);

		Intent myResultIntent = new Intent(DNIeReaderActivity.this, DNIeErrorActivity.class);
		myResultIntent.putExtras(b);
		startActivity(myResultIntent);
	}

	public class TaskLoadDG extends AsyncTask<Void, Integer, Void> {

		private boolean mHasErrors = false;

		@Override
		protected void onPreExecute() {
			// Clean Controls
			mHandler.post(newRead);

			// Prepare auto-reset for possible reading failure
			mForceReset = true;

			// Set Animation to Reading
			mTextProcess = getApplicationContext().getString(R.string.process_msg_dni);
			//setMode(MODE_READING);
		}

		@Override
		protected void onProgressUpdate(Integer... values) {
			// TODO Auto-generated method stub
			super.onProgressUpdate(values);

			mAnimInfoText.setText(mTextProcess);
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
				mForceReset = true;
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
			mKSUserMrtd = null;

			// Read again NFC Card... perhaps moved.
			if (mForceReset) {
				mHandler.post(askForRead);
				return;
			}

			if (mHasErrors)
				HandleError(mTextResultPage);
			else {
				mDocumentReaded = true;
				setMode(MODE_COMPLETE);
			}
		}
	}

	private void setMode(int mode) {
		boolean isSimpleMode = (mode == MODE_COMPLETE);

		findViewById(R.id.textInfo).setVisibility(isSimpleMode || mode == MODE_ERROR ? View.INVISIBLE : View.VISIBLE);
		findViewById(R.id.textResultExtra).setVisibility(isSimpleMode ? View.VISIBLE : View.INVISIBLE);
		findViewById(R.id.btnNext).setVisibility(isSimpleMode ? View.VISIBLE : View.INVISIBLE);
		findViewById(R.id.btnBack).setVisibility(isSimpleMode ? View.INVISIBLE : View.VISIBLE);
		findViewById(R.id.textResult).setVisibility(mode == MODE_READING ? View.INVISIBLE : View.VISIBLE);

		//Control DNIe Read Anim Visbility
		if (mode != MODE_READING) {
			mValueAnimatorBall1.cancel();
			mValueAnimatorBall2.cancel();
			mValueAnimatorBall3.cancel();
			findViewById(R.id.animDNIe_ball_1).setVisibility(View.INVISIBLE);
			findViewById(R.id.animDNIe_ball_2).setVisibility(View.INVISIBLE);
			findViewById(R.id.animDNIe_ball_3).setVisibility(View.INVISIBLE);
		}
		findViewById(R.id.imgDNIe).setVisibility(mode == MODE_READING ? View.VISIBLE : View.INVISIBLE);

		if (mode == MODE_WAITING) {
			changeAnimation(R.drawable.animated_start_read_dnie);
		} else if (mode == MODE_COMPLETE) {
			changeAnimation(R.drawable.animated_completed_dnie);
			TextView textResultExtra = findViewById(R.id.textResultExtra);
			((TextView) findViewById(R.id.textResult)).setText(R.string.op_finished);
			textResultExtra.setText(R.string.op_finished_info);
			Bitmap mLoadedImage = null;
			ImageView imgPhoto = findViewById(R.id.photo);
			imgPhoto.setVisibility(View.VISIBLE);
			if (mDG2 != null) {
				try {
					// JPEG-2000 Parse
					byte [] imagen = mDG2.getImageBytes();
					J2kStreamDecoder j2k = new J2kStreamDecoder();
					ByteArrayInputStream bis = new ByteArrayInputStream(imagen);
					mLoadedImage = j2k.decode(bis);
				} catch(Exception e) {
					e.printStackTrace();
				}
			}
			if (mLoadedImage != null)
				setPhoto(new BitmapDrawable(getResources(), mLoadedImage));
			else
				imgPhoto.setImageResource(R.drawable.noface);
			vibrate(VIBRATE_TIME_MS);
			mSoundSuccess.start();
		} else if (mode == MODE_READING) {
			changeAnimation(R.drawable.animated_reading_dnie);
			final ImageView imgDNIe = findViewById(R.id.imgDNIe);
			imgDNIe.setAlpha(0.0f);
			imgDNIe.setTranslationY(200.0f);
			imgDNIe.animate().setDuration(800).translationY(-200.0f).alpha(1.0f).start();


			mValueAnimatorBall1.setStartDelay(800);
			mValueAnimatorBall1.start();
			mValueAnimatorBall2.setStartDelay(950);
			mValueAnimatorBall2.start();
			mValueAnimatorBall3.setStartDelay(1300);
			mValueAnimatorBall3.start();

			((TextView)findViewById(R.id.textResult)).setText(R.string.process_msg_lectura);
		} else if (mode == MODE_ERROR) {
			mSoundError.start();
			((TextView)findViewById(R.id.textResult)).setText(R.string.op_reinit);
			changeAnimation(R.drawable.animated_error_dnie);
		}
	}

	public void vibrate(final int milis) {
		Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			v.vibrate(VibrationEffect.createOneShot(milis, VibrationEffect.DEFAULT_AMPLITUDE));
		} else {
			//deprecated in API 26
			v.vibrate(milis);
		}
	}

	private void setPhoto(Drawable replace) {
		ImageView photo = findViewById(R.id.photo);
		photo.setImageDrawable(replace);
		photo.setScaleX(0.3f);
		photo.setScaleY(0.3f);
		photo.animate().alpha(1.0f).scaleX(1.0f).scaleY(1.0f).setStartDelay(250);
	}

	private void changeAnimation(int animIndex) {
		Drawable anim = ContextCompat.getDrawable(DNIeReaderActivity.this, animIndex);
		ImageView animInfo = findViewById(R.id.animInfo);
		animInfo.setImageDrawable(anim);
		((Animatable)animInfo.getDrawable()).start();
	}

	@Override
	public void onCreate(Bundle savedState) {
		super.onCreate(savedState);

		// Remove titlebar
		this.requestWindowFeature(Window.FEATURE_NO_TITLE);
		setContentView(R.layout.activity_dnie_reader);

		mTagFromIntent = null;

		mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
		mNfcAdapter.setNdefPushMessage(null, this);
		mNfcAdapter.setNdefPushMessageCallback(null, this);

		mDG1 = null;
		mDG2 = null;
		mDG7 = null;
		mDG11 = null;

		findViewById(R.id.textResultExtra).setVisibility(TextView.INVISIBLE);

		mCANDOS = new CANSpecDOStore(this);
		mCANDnie = ((AppMain)getApplicationContext()).getCAN();

		mAnimDNIeBall1 = findViewById(R.id.animDNIe_ball_1);
		mAnimDNIeBall2 = findViewById(R.id.animDNIe_ball_2);
		mAnimDNIeBall3 = findViewById(R.id.animDNIe_ball_3);

		final PropertyValuesHolder valTranslateY = PropertyValuesHolder.ofFloat("translateY", 0f, -300f);
		final PropertyValuesHolder valAlpha = PropertyValuesHolder.ofFloat("alpha", 1f, 0f);
		final int animDuration = 1000;

		/* DNIe Anim Ball 1 */
		mValueAnimatorBall1 = ValueAnimator.ofPropertyValuesHolder(valTranslateY, valAlpha);
		mValueAnimatorBall1.setInterpolator(new AccelerateDecelerateInterpolator());
		mValueAnimatorBall1.setDuration(animDuration);
		mValueAnimatorBall1.setRepeatCount(ValueAnimator.INFINITE);
		mValueAnimatorBall1.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
			@Override
			public void onAnimationUpdate(ValueAnimator animation) {
				mAnimDNIeBall1.setVisibility(View.VISIBLE);
				float progress = (float) animation.getAnimatedValue("translateY");
				float alpha = (float) animation.getAnimatedValue("alpha");
				mAnimDNIeBall1.setTranslationY(progress);
				mAnimDNIeBall1.setAlpha(alpha);
			}
		});
		/* DNIe Anim Ball 2 */
		mValueAnimatorBall2 = ValueAnimator.ofPropertyValuesHolder(valTranslateY, valAlpha);
		mValueAnimatorBall2.setInterpolator(new AccelerateDecelerateInterpolator());
		mValueAnimatorBall2.setDuration(animDuration);
		mValueAnimatorBall2.setRepeatCount(ValueAnimator.INFINITE);
		mValueAnimatorBall2.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
			@Override
			public void onAnimationUpdate(ValueAnimator animation) {
				mAnimDNIeBall2.setVisibility(View.VISIBLE);
				float progress = (float) animation.getAnimatedValue("translateY");
				float alpha = (float) animation.getAnimatedValue("alpha");
				mAnimDNIeBall2.setTranslationY(progress);
				mAnimDNIeBall2.setAlpha(alpha);
			}
		});
		/* DNIe Anim Ball 3 */
		mValueAnimatorBall3 = ValueAnimator.ofPropertyValuesHolder(valTranslateY, valAlpha);
		mValueAnimatorBall3.setInterpolator(new AccelerateDecelerateInterpolator());
		mValueAnimatorBall3.setDuration(animDuration);
		mValueAnimatorBall3.setRepeatCount(ValueAnimator.INFINITE);
		mValueAnimatorBall3.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
			@Override
			public void onAnimationUpdate(ValueAnimator animation) {
				mAnimDNIeBall3.setVisibility(View.VISIBLE);
				float progress = (float) animation.getAnimatedValue("translateY");
				float alpha = (float) animation.getAnimatedValue("alpha");
				mAnimDNIeBall3.setTranslationY(progress);
				mAnimDNIeBall3.setAlpha(alpha);
			}
		});

		TextView myText = findViewById(R.id.textResultExtra);
		myText.setVisibility(TextView.INVISIBLE);
		myText.setTypeface(mFontType);

		Button btnNFCBack = findViewById(R.id.btnBack);
		btnNFCBack.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				onBackPressed();
			}
		});

		Button btnNFCNext = findViewById(R.id.btnNext);
		btnNFCNext.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				if (!mDocumentReaded)
					return;

				mNfcAdapter.disableReaderMode(DNIeReaderActivity.this);
				Bundle b = new Bundle();
				if (mDG1 != null) b.putByteArray("DGP_DG1", mDG1.getBytes());
				if (mDG2 != null) b.putByteArray("DGP_DG2", mDG2.getBytes());
				if (mDG7 != null) b.putByteArray("DGP_DG7", mDG7.getBytes());
				if (mDG11 != null) b.putByteArray("DGP_DG11", mDG11.getBytes());


				Intent myResultIntent = new Intent(DNIeReaderActivity.this, DNIeResultActivity.class);
				myResultIntent.putExtras(b);
				ActivityOptionsCompat options = ActivityOptionsCompat.
						makeSceneTransitionAnimation(DNIeReaderActivity.this, findViewById(R.id.photo), "photo-img");
				startActivityForResult(myResultIntent, 1, options.toBundle());
				finish();
			}
		});

		mAnimInfoText = findViewById(R.id.textInfo);
		mAnimInfo = findViewById(R.id.animInfo);
		setMode(MODE_WAITING);

		// Sounds
		mSoundError = MediaPlayer.create(this, R.raw.error);
		mSoundSuccess = MediaPlayer.create(this, R.raw.success);
	}

	@Override
	public void onResume() {
		super.onResume();
		if (!mReaderModeON)
			mReaderModeON = EnableReaderMode(1000);
	}

	@Override
	public void onPause() {
		super.onPause();
		if (mReaderModeON) {
			mReaderModeON = false;
			mNfcAdapter.disableReaderMode(this);
		}
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if ((keyCode == KeyEvent.KEYCODE_BACK)) {
			Intent intent = new Intent(DNIeReaderActivity.this, ReadModeActivity.class);
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
		mNfcAdapter.enableReaderMode(this,
				this,
				NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK | NfcAdapter.FLAG_READER_NFC_B,
				options);
		return true;
	}

	@Override
	public void onTagDiscovered(Tag tag) {
		try {
			mTagFromIntent = tag;
			TaskLoadDG newTask = new TaskLoadDG();
			newTask.execute();
		} catch (Exception e)
		{
			mTextResultPage = getApplicationContext().getString(R.string.nfc_error_files) + "\n" + e.getMessage();
		}
	}

	public void LoadDGs() throws Exception
	{
		try
		{
			// Read DG1 & DG11 data
			mTextProcess = getApplicationContext().getString(R.string.nfc_reading);
			mHandler.post(updateStatus);

			// Enable fast-mode
			System.setProperty("es.gob.jmulticard.fastmode", "true");

			// Load DNie services provider
			final DnieProvider p = new DnieProvider();
			p.setProviderTag(mTagFromIntent);
			StringBuilder can6digitos = new StringBuilder(mCANDnie.getCanNumber());
			while (can6digitos.length() < 6)
				can6digitos.insert(0, "0");
			p.setProviderCan(can6digitos.toString());
			Security.insertProviderAt(p, 1);

			// Create DNIe Key Store
			KeyStoreSpi ksSpi = new MrtdKeyStoreImpl();
			mKSUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");
			mKSUserMrtd.load(null, null);

			// Read EF_COM to know available data on the document
			try{
				EF_COM m_efcom = mKSUserMrtd.getEFCOM();
				byte[] tagList = m_efcom.getTagList();

				for (byte b : tagList) {
					switch (b) {
						case 0x61:
							// DG_1
							mExistsDG1 = true;
							break;
						case 0x75:
							// DG_2
							mExistsDG2 = true;
							break;
						case 0x67:
							// DG_7
							mExistsDG7 = true;
							break;
						case 0x6B:
							// DG_11
							mExistsDG11 = true;
							break;
					}
				}
			} catch (Exception e)
			{
				e.printStackTrace();
				throw e;
			}

			// Read available DG's
			if (mExistsDG1) {
				try {
					mDG1 = mKSUserMrtd.getDatagroup1();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

			if (mExistsDG11) {
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
				CANSpecDO currentCan = new CANSpecDO(mCANDnie.getCanNumber(), certSubject, docNumber);
				mCANDOS.delete(mCANDnie);
				mCANDOS.save(currentCan);
			}

			if (mExistsDG2)
			{
				try {
					mTextProcess = getApplicationContext().getString(R.string.nfc_reading_photo);
					mHandler.post(updateStatus);

					mDG2 = mKSUserMrtd.getDatagroup2();

				} catch (Exception e)
				{
					e.printStackTrace();
					throw e;
				}
			}

			if (mExistsDG7) {
				try {
					mTextProcess = getApplicationContext().getString(R.string.nfc_reading_signature);
					mHandler.post(updateStatus);

					mDG7 = mKSUserMrtd.getDatagroup7();
				} catch (Exception e) {
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
					mTextResultPage +=  getApplicationContext().getString(R.string.nfc_error_lost);
					throw new Exception(mTextResultPage);
				}

				mTextResultPage += e.getMessage();
			}

			throw new Exception(mTextResultPage);
		}
	}

}
