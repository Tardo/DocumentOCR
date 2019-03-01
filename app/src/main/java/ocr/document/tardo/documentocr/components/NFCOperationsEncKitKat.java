package ocr.document.tardo.documentocr.components;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
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
public class NFCOperationsEncKitKat extends Activity implements ReaderCallback
{
	// NFC Adapter
    static private NfcAdapter myNfcAdapter = null;

    // Gestión del CAN
    private CANSpecDO canDnie;
    private CANSpecDOStore cansDO;
    private Activity myActivity;

    private boolean m_readDg1;
    private boolean m_readDg2;
    private boolean m_readDg7;
    private boolean m_readDg11;
    private boolean m_readDg13;

    // Variables miembro de los ficheros disponibles en el documento
    private boolean m_existDg1;
    private boolean m_existDg2;
    private boolean m_existDg7;
    private boolean m_existDg11;

    private DG1_Dnie    m_dg1;
    private DG11        m_dg11;
    private DG2         m_dg2;
    private DG7         m_dg7;

    private boolean readerModeON = false;

    private DnieKeyStore m_ksUserMrtd = null;

    final Handler myHandler = new Handler();
    private ProgressDialog progressBar;

	private Tag tagFromIntent=null;

    Typeface fontType;
    private String textoProcessDlg;
    private String textoResultPage;

    private boolean mForzamosReinicio  = true;

    final Runnable updateStatus = new Runnable() {
        public void run()
        {
            progressBar.setMessage(textoProcessDlg);
            if(!progressBar.isShowing())
                progressBar.show();
        }
    };

    final Runnable askForRead = new Runnable()
    {
        public void run()
        {
            textoResultPage ="";
            textoResultPage ="";
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
            textoResultPage ="";
            textoResultPage ="";
            ((TextView)findViewById(R.id.textResult)).setText(R.string.process_msg_lectura);
            findViewById(R.id.textResult).setVisibility(TextView.VISIBLE);
            ((ImageView)findViewById(R.id.imgResult)).setImageResource(R.drawable.btn_aproxdnie);
            findViewById(R.id.imgResult).setVisibility(ImageView.VISIBLE);
            findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);
        }
    };

    public void HandleError(String strError)
    {
        // Pasamos los datos a la activity correspondiente
        Bundle b = new Bundle();
        b.putString("ERROR_MSG", strError);

        Intent myResultIntent = new Intent(NFCOperationsEncKitKat.this, DNIeErrorActivity.class);
        myResultIntent.putExtras(b);
        startActivity(myResultIntent);
    }

    public class MyTaskDG11 extends AsyncTask<Void, Integer, Void> {

        private boolean bHayErrores = false;

        @Override
        protected void onPreExecute()
        {
            // Limpiamos controles
            myHandler.post(newRead);

            // Preparamos el reinicio automático por si fallase la lectura
            mForzamosReinicio = true;

            // Lanzamos el diálogo con el progreso
            progressBar.setIndeterminate(true);
            progressBar.setCancelable(false);
            progressBar.setTitle(R.string.process_title);
            progressBar.setMessage(getApplicationContext().getString(R.string.process_msg_dni));
            textoProcessDlg=getApplicationContext().getString(R.string.process_msg_dni);
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            // TODO Auto-generated method stub
            super.onProgressUpdate(values);

            progressBar.setMessage(textoProcessDlg);
            if(!progressBar.isShowing())
                progressBar.show();
        }

        @Override
        protected Void doInBackground(Void... params) {

            //////////////////////////////////////////////////////////////////////////////////
            // PASO 0: Leemos los Data Groups con los datos públicos del documento
            //
            try {
                // Lanzamos la operación de lectura del DNIe
                CargarDGs();

                mForzamosReinicio = false;
            }
            catch (PaceException e)
            {
                // Si el código CAN es incorrecto, mostramos el error.
                textoResultPage     = e.getMessage();
                mForzamosReinicio   = false;
                bHayErrores         = true;

                return null;
            }
            catch (Exception e)
            {
                textoResultPage = "Ocurrió un error durante la lectura de los DGs.";
                if (e.getMessage()!=null)
                {
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
        protected void onPostExecute(Void result)
        {
            // Destruimos el cuadro de diálogo
            progressBar.dismiss();

            // Eliminamos el rovider del DNI electrónico
            m_ksUserMrtd = null;

            // Si no hemos presentado el PIN aún, permitimos que se continuen las lecturas.
            // Es posible que el DNIe se haya movido sin querer así que entendemos que
            // el usuario no da por finalizada la operación
            if(mForzamosReinicio) {
                // Repintamos la pantalla
                myHandler.post(askForRead);

                // Habilitamos la comprobación de presencia NFC a 250 milis
                readerModeON = EnableReaderMode(250);
                return;
            }

            // Si hubo algún error que provocó el fin del proceso, lo mostramos
            if(bHayErrores)
            {
                HandleError(textoResultPage);
                return;
            }

            //Creamos la información a pasar entre actividades
            Bundle b = new Bundle();
            if(m_dg1!=null) b.putByteArray("DGP_DG1",   m_dg1.getBytes());
            if(m_dg2!=null) b.putByteArray("DGP_DG2",   m_dg2.getBytes());
            if(m_dg7!=null) b.putByteArray("DGP_DG7",   m_dg7.getBytes());
            if(m_dg11!=null)b.putByteArray("DGP_DG11",  m_dg11.getBytes());

            // Pasamos los datos a la activity correspondiente
            Intent myResultIntent = new Intent(NFCOperationsEncKitKat.this, DNIeResultActivity.class);
            myResultIntent.putExtras(b);
            startActivityForResult(myResultIntent, 1);
        }
    }

    @Override
    public void onCreate(Bundle savedState) {
        super.onCreate(savedState);

        // Quitamos la barra del título
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.component_dnie_read_kitkat);

        // Inicializamos controles
        tagFromIntent 	= null;

        Context myContext = NFCOperationsEncKitKat.this;
        myActivity 		= ((Activity) myContext);

        // Obtenemos el adaptador NFC
        myNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        myNfcAdapter.setNdefPushMessage(null, this);
        myNfcAdapter.setNdefPushMessageCallback(null, this);

        // Inicializamos los Data Groups
        m_dg1 = null;
        m_dg2 = null;
        m_dg7 = null;
        m_dg11 = null;

        // Lanzamos el diálogo con el progreso
        progressBar = new ProgressDialog(myContext);

        // Limpiamos controles
        findViewById(R.id.infoResult).setVisibility(TextView.INVISIBLE);

        // Conexión con el DNIe
        cansDO 	= new CANSpecDOStore(this);
        canDnie = ((AppMain)getApplicationContext()).getCAN();

        TextView myText = (TextView) findViewById(R.id.infoResult);
        myText.setVisibility(TextView.INVISIBLE);
        myText.setTypeface(fontType);

		///////////////////////////////////////////////////////////////////////////////////
		// Botón de vuelta al Activity anterior
    	Button btnNFCBack = (Button)findViewById(R.id.btnBack);
    	btnNFCBack.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {

				// Volvemos al activity padre
                onBackPressed();
			}
		});
    }

    @Override
    public void onResume() {
        super.onResume();
        if(!readerModeON)
            readerModeON = EnableReaderMode(1000);
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if ((keyCode == KeyEvent.KEYCODE_BACK)) {
        	// Devolvemos el valor del m�dulo al Activity padre
			Intent intent = new Intent(NFCOperationsEncKitKat.this, ReadModeActivity.class);
	        startActivity(intent);
	        return false;
        }
        else
        	return super.onKeyDown(keyCode, event);
    }

    private boolean EnableReaderMode (int msDelay)
    {
        // Ponemos en msDelay milisegundos el tiempo de espera para comprobar presencia de lectores NFC
        Bundle options = new Bundle();
        options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, msDelay);
        myNfcAdapter.enableReaderMode(myActivity,
                this,
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
                        NfcAdapter.FLAG_READER_NFC_B,
                options);
        return true;
    }

    private boolean DisableReaderMode()
    {
        // Desactivamos el modo reader de NFC
        myNfcAdapter.disableReaderMode(this);
        readerModeON = false;
        return true;
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        try {
            tagFromIntent = tag;

            MyTaskDG11 newTask = new MyTaskDG11();
            newTask.execute();

        } catch (Exception e)
        {
            textoResultPage = "Ocurrió un error durante la lectura de ficheros.\n"+e.getMessage();
        }
    }

    public boolean CargarDGs() throws PaceException, Exception
    {
        try
        {
            // Leemos los datos del DG1 y DG11
            textoProcessDlg="Leyendo datos...";
            myHandler.post(updateStatus);

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
            m_ksUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");
            m_ksUserMrtd.load(null, null);

            // Leemos la configuración para saber qué datos debemos obtener y cargar sólo los DGs que nos hayan solicitado
            readUserConfiguration();

            ////////////////////////////////////////////////
            // Leemos el EF_COM para saber qué datos hay disponibles en el documento
            try{
                EF_COM m_efcom = m_ksUserMrtd.getEFCOM();
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
                if (e.getMessage().contains("CAN incorrecto")) {
                    textoResultPage = "Error al montar canal PACE. CAN incorrecto.";
                    throw new PaceException(textoResultPage);
                }

                if (e.getMessage().contains("Tag was lost")) {
                    textoResultPage += "Se perdió la conexión inalámbrica con el DNI electrónico.";
                    throw new Exception(textoResultPage);
                }

                textoResultPage += e.getMessage();
            }

            throw new Exception(textoResultPage);
        }

        return true;
    }


    void readUserConfiguration()
    {
        // Actualizamos los valores mostrados para cuenta y contraseña
        SharedPreferences sharedPreferences = getApplicationContext().getSharedPreferences("com.sp.main_preferences", Context.MODE_PRIVATE);

        // Recupera los valores de lectura de DGs
        m_readDg1  = true;
        m_readDg2  = true;
        m_readDg7  = true;
        m_readDg11 = true;
        m_readDg13 = true;
    }
}
