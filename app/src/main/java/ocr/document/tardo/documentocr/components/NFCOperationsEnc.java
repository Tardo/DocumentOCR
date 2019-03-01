package ocr.document.tardo.documentocr.components;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ComponentName;
import android.content.Context;
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

/////////////////////////////////////////////
public class NFCOperationsEnc extends Activity {
	// Tecnologías posibles sobre las que trabajar
	private NfcA exNfcA;
	private NfcB exNfcB;
	private IsoDep exIsoDep;

	private Context myContext;

	private Tag tagFromIntent = null;
	private boolean m_bRestart = false;

	private ProgressDialog progressDlg;
	final Handler myHandler = new Handler();

	private boolean m_readDg1;
	private boolean m_readDg2;
	private boolean m_readDg7;
	private boolean m_readDg11;

	// Variables miembro de los ficheros disponibles en el documento
	private boolean m_existDg1;
	private boolean m_existDg2;
	private boolean m_existDg7;
	private boolean m_existDg11;

	// Objetos con los Data Groups del DNIe
	private EF_COM m_efcom;
	private DG1_Dnie m_dg1;
	private DG11 m_dg11;
	private DG2 m_dg2;
	private DG7 m_dg7;

	private String textoProcessDlg;
	private String textoResultPage;

	final Runnable updateStatus = new Runnable() {
		public void run() {
			progressDlg.setMessage(textoProcessDlg);
		}
	};

	final Runnable cleanFragment = new Runnable() {
		public void run()
		{
			textoResultPage ="";
			textoResultPage ="";
			((TextView)findViewById(R.id.result1)).setText(R.string.process_msg_lectura);
			findViewById(R.id.result1).setVisibility(TextView.VISIBLE);
			((ImageView)findViewById(R.id.imgResult)).setImageResource(R.drawable.btn_aproxdnie);
			findViewById(R.id.imgResult).setVisibility(ImageView.VISIBLE);
			findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);
		}
	};

	public class MyTaskDNIe extends AsyncTask<Void, Integer, Void> {
		private boolean bCompleted = false;

		@Override
		protected void onPreExecute() {
			bCompleted = false;

			// Limpiamos controles
			myHandler.post(cleanFragment);

			// Lanzamos el diálogo con el progreso
			progressDlg.setIndeterminate(true);
			progressDlg.setCancelable(false);
			progressDlg.setTitle("DNIe version 3.0");
			progressDlg.setMessage("Leyendo DNIe...");
			progressDlg.show();
		}

		@Override
		protected Void doInBackground(Void... arg0) {
			//////////////////////////////////////////////////////////////////////////////////
			// PASO 0: Leemos el DG.1 con los datos públicos del documento pasaporte
			// y pedimios la confirmación del usuario para continuar
			//
			try {
				// Lanzamos la operación de lectura del DNIe
				CargarDGs();

				bCompleted = true;
			} catch (PaceException e) {
				// Si el código CAN es incorrecto, mostramos el error.
				textoResultPage     = e.getMessage();
				return null;
			} catch (Exception e) {
				textoResultPage = "Ocurrió un error durante la lectura de los DGs.";

				if (e.getMessage() != null) {
					if (e.getMessage().contains("lost"))
						textoResultPage = "Error de comunicación. Se ha perdido la conexión con el DNIe.";
					else
						textoResultPage = e.getMessage();
				}
				return null;
			}

			return null;
		}

		@Override
		protected void onPostExecute(Void result) {
			// Si la operación se detuvo inesperadamente, salimos.
			if (!bCompleted) {
				// Destruimos el cuadro de diálogo
				progressDlg.dismiss();

				// Mostramos el error
				HandleError(textoResultPage);

				return;
			}

			m_bRestart = false;

			//Creamos la información a pasar entre actividades
			Bundle b = new Bundle();
			if(m_dg1!=null) b.putByteArray("DGP_DG1",   m_dg1.getBytes());
			if(m_dg11!=null)b.putByteArray("DGP_DG11",  m_dg11.getBytes());
			if(m_dg2!=null) b.putByteArray("DGP_DG2",   m_dg2.getBytes());
			if(m_dg7!=null) b.putByteArray("DGP_DG7",   m_dg7.getBytes());

			// Pasamos los datos a la activity correspondiente
			Intent myResultIntent = new Intent(NFCOperationsEnc.this, DNIeResultActivity.class);
			myResultIntent.putExtras(b);
			startActivity(myResultIntent);
		}
	}

	@Override
	public void onCreate(Bundle savedState) {
		super.onCreate(savedState);

		// Si no hemos abierto correctamente, salimos
		if (!((AppMain) getApplicationContext()).isStarted()) {
			Toast.makeText(getApplicationContext(), "Esta aplicación había quedado abierta irregularmente. Salimos.\n", Toast.LENGTH_LONG).show();

			// Desactivamos la activity ENABLE = false
			PackageManager packman = getApplicationContext().getPackageManager();
			ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
			packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0);//*/

			android.os.Process.killProcess(android.os.Process.myPid());
			System.exit(0);

			return;
		}

		// Quitamos la barra del título
		this.requestWindowFeature(Window.FEATURE_NO_TITLE);
		setContentView(R.layout.component_dnie_read);

		// Almacenamos el contexto de la Activity
		myContext = NFCOperationsEnc.this;
		tagFromIntent = null;
		progressDlg = new ProgressDialog(NFCOperationsEnc.this);

		Intent intent = getIntent();
		resolveIntent(intent);

		if (tagFromIntent == null) {
			return;
		}

		// Interfaz NfcA o NfcB
		if ((exNfcA != null) ||
				(exNfcB != null)) {
			if (exIsoDep != null) {
				exIsoDep.setTimeout(3000);

				MyTaskDNIe newTask = new MyTaskDNIe();
				newTask.execute();
			}
		}


		///////////////////////////////////////////////////////////////////////////////////
		// Botón de vuelta al Activity anterior
		Button btnNFCBack = (Button) findViewById(R.id.btnBack);

		btnNFCBack.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {

				// Volvemos al Activity de presentación del DNIe
				Intent intent = new Intent(NFCOperationsEnc.this, DNIeCANActivity.class);
				startActivity(intent);
			}
		});

	}

	@Override
	protected void onStart() {
		// TODO Auto-generated method stub
		super.onStart();

		// Activamos la activity ENABLE = true
		PackageManager packman = getApplicationContext().getPackageManager();
		ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
		packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);//*/

		if (m_bRestart) {
			// Si no hemos abierto correctamente, salimos
			if (!((AppMain) getApplicationContext()).isStarted()) {
				Toast.makeText(getApplicationContext(), "Esta aplicación había quedado abierta irregularmente. Salimos.\n", Toast.LENGTH_SHORT).show();
				android.os.Process.killProcess(android.os.Process.myPid());
				System.exit(0);
				return;
			}

			if (tagFromIntent == null) {
				return;
			}

			// Interfaz NfcA o NfcB
			if ((exNfcA != null) ||
					(exNfcB != null)) {
				if (exIsoDep != null) {
					exIsoDep.setTimeout(3000);

					MyTaskDNIe newTask = new MyTaskDNIe();
					newTask.execute();
				}
			}
		}
	}

	@Override
	protected void onStop() {
		// TODO Auto-generated method stub
		super.onStop();

		// Activamos la activity ENABLE = true
		PackageManager packman = getApplicationContext().getPackageManager();
		ComponentName componentName = new ComponentName(getApplicationContext(), NFCOperationsEnc.class);
		packman.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
	}

	void resolveIntent(Intent intent) {

		tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		if (tagFromIntent != null) {
			// Obtenemos las tecnologías disponibles
			exNfcA = NfcA.get(tagFromIntent);
			exNfcB = NfcB.get(tagFromIntent);
			exIsoDep = IsoDep.get(tagFromIntent);
		}
	}

	@Override
	public void onNewIntent(Intent intent) {
		setIntent(intent);
		resolveIntent(intent);

		// Indicamos que ya se ha creado el Intent así que habrá que reiniciarlo, simplemente.
		m_bRestart = true;
	}

	private void HandleError(String strError) {
		// Pasamos los datos a la activity correspondiente
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
			// Leemos los datos del DG11
			textoProcessDlg="Leyendo datos...";
			myHandler.post(updateStatus);

			// Conexión con el DNIe
			CANSpecDOStore cansDO = new CANSpecDOStore(this);
			CANSpecDO canDnie = ((AppMain) getApplicationContext()).getCAN();

			// Activamos el modo rápido para agilizar la carga.
			System.setProperty("es.gob.jmulticard.fastmode", "true");

			// Cargamos el proveedor de servicios del DNIe
			final DnieProvider p = new DnieProvider();
			p.setProviderTag(tagFromIntent);
			String can6digitos = canDnie.getCanNumber();
			while(can6digitos.length()<6)
				can6digitos = "0"+can6digitos;
			p.setProviderCan(can6digitos);
			Security.insertProviderAt(p, 1);

			// Creamos el DnieKeyStore
			KeyStoreSpi ksSpi = new MrtdKeyStoreImpl();
			DnieKeyStore m_ksUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");
			m_ksUserMrtd.load(null, null);

			// Leemos la configuración para saber qué datos debemos obtener y cargar sólo los DGs que nos hayan solicitado
			readUserConfiguration();

			////////////////////////////////////////////////
			// Leemos el EF_COM para saber qué datos hay disponibles en el documento
			try{
				m_efcom  = m_ksUserMrtd.getEFCOM();

				byte[] tagList = m_efcom.getTagList();

				for(int idx=0;idx<tagList.length;idx++) {
					switch (tagList[idx]){
						case 0x61:
							// DG_1. Lo leemos siempre que esté disponible
							m_existDg1 = true;
							break;
						case 0x75:
							// DG_2. Lo leemos si el usuario lo especificó
							m_existDg2 = true;
							break;
						case 0x67:
							// DG_7. Lo leemos si el usuario lo especificó
							m_existDg7 = true;
							break;
						case 0x6B:
							// DG_11. Lo leemos siempre que esté disponible
							m_existDg11 = true;
							break;
					}
				}

			}catch (Exception e)
			{
				e.printStackTrace();
				throw e;
			}

			////////////////////////////////////////////////
			// Leemos el DG1
			try{
				if(m_readDg1&&m_existDg1)
					m_dg1  = m_ksUserMrtd.getDatagroup1();
			}catch (Exception e)
			{
				e.printStackTrace();
			}

			////////////////////////////////////////////////
			// Leemos el DG11
			try{
				if(m_readDg11&&m_existDg11)
					m_dg11 = m_ksUserMrtd.getDatagroup11();
			}catch (Exception e)
			{
				e.printStackTrace();
			}

			// Actualizamos la BBDD de los CAN para añadir estos datos si no estuvieran
			if(canDnie.getUserNif().length()==0)
			{
				String docNumber;
				String certSubject = m_dg1.getName() + " " + m_dg1.getSurname();
				if (m_dg11 == null)
					docNumber = m_dg1.getDocNumber();
				else
					docNumber = m_dg11.getPersonalNumber();
				CANSpecDO newCan = new CANSpecDO(canDnie.getCanNumber(), certSubject, docNumber);
				cansDO.delete(canDnie);
				cansDO.save(newCan);
			}

			////////////////////////////////////////////////
			// Leemos el DG2
			if(m_readDg2&&m_existDg2)
			{
				try{
					// Leemos los datos del DG2
					textoProcessDlg = "Cargando foto...";
					myHandler.post(updateStatus);

					// Obtenemos la imagen del ciudadano
					m_dg2 = m_ksUserMrtd.getDatagroup2();

				}catch (Exception e)
				{
					e.printStackTrace();
					throw e;
				}
			}

			////////////////////////////////////////////////
			// Leemos el DG7
			if(m_readDg7&&m_existDg7)
			{
				try{
					// Leemos los datos del DG7
					textoProcessDlg = "Cargando firma...";
					myHandler.post(updateStatus);

					// Obtenemos la imagen del ciudadano
					m_dg7 = m_ksUserMrtd.getDatagroup7();
				}catch (Exception e)
				{
					e.printStackTrace();
					throw e;
				}
			}
		}
		catch(Exception e)
		{
			textoResultPage = "Ocurrió un error durante la lectura de los DGs.\n";
			if(e.getMessage()!=null) {
				if (e.getMessage().contains("Tag was lost"))
					textoResultPage += "Se perdió la conexión inalámbrica con el DNI electrónico.";
				else
					textoResultPage += e.getMessage();
			}
			throw new Exception(textoResultPage);
		}
		return true;
	}

	void readUserConfiguration()
	{
		m_readDg1  = true;
		m_readDg2  = true;
		m_readDg7  = true;
		m_readDg11 = true;
	}
}
