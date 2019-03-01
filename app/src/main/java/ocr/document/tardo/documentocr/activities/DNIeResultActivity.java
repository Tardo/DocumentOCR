/* Copyright 2019  Alexandre Díaz - <dev@redneboa.es>
 * Original code from https://www.dnielectronico.es/descargas/Apps/Android_DGPApp_LECTURA.rar
 *
 * License GPL-3.0 or later (http://www.gnu.org/licenses/gpl.html).
 */
package ocr.document.tardo.documentocr.activities;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Base64;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.eiqui.odoojson_rpc.JSONRPCClientOdoo;
import com.eiqui.odoojson_rpc.exceptions.OdooSearchException;

import org.json.JSONArray;
import org.json.JSONException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import ocr.document.tardo.documentocr.AppMain;
import ocr.document.tardo.documentocr.R;
import ocr.document.tardo.documentocr.utils.DateHelper;
import ocr.document.tardo.documentocr.utils.jj2000.J2kStreamDecoder;

public class DNIeResultActivity extends Activity implements View.OnClickListener {

    public DG1_Dnie m_dg1;
    public DG11     m_dg11;
    private DG2     m_dg2;
    private DG7     m_dg7;

    public Bitmap mLoadedImage;
    private Bitmap mLoadedSignature;

    private Button mButtonBack;
    private Button mButtonStartRead;

    private HandlerThread mBackgroundThread;
    private Handler mBackgroundHandler;

    private SimpleDateFormat sdFormat = new SimpleDateFormat("yyMMdd");

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Quitamos la barra del título
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_dnie_result);

        // Almacenamos el contexto
        Context myContext = DNIeResultActivity.this;

        Bundle extras = getIntent().getExtras();
        if(extras != null) {

            // Recuperamos los datos obtenidos en la lectura anterior
            byte [] m_dataDG1	= extras.getByteArray("DGP_DG1");
            byte []  m_dataDG2	= extras.getByteArray("DGP_DG2");
            byte [] m_dataDG7	= extras.getByteArray("DGP_DG7");
            byte [] m_dataDG11 	= extras.getByteArray("DGP_DG11");

            // Construimos los objetos Data Group que hayamos leído
            if(m_dataDG1!=null) m_dg1   = new DG1_Dnie(m_dataDG1);
            if(m_dataDG2!=null) m_dg2   = new DG2(m_dataDG2);
            if(m_dataDG7!=null) m_dg7   = new DG7(m_dataDG7);
            if(m_dataDG11!=null)m_dg11  = new DG11(m_dataDG11);

            TextView tvloc;
            ////////////////////////////////////////////////////////////////////////
            // Información del DG1, si la tenemos
            if(m_dg1!=null) {
                // Nombre
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_01);
                tvloc.setText(m_dg1.getName());
                // Apellidos
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_02);
                tvloc.setText(m_dg1.getSurname());
                // Doc Number
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_03);
                tvloc.setText(m_dg1.getDocNumber());
                // Doc caducity
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_03_caducity);
                tvloc.setText(m_dg1.getDateOfExpiry());
                // Doc emision
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_10);
                try {
                    DateFormat dtFormat = DateFormat.getDateInstance(2);
                    Date expiryDate = dtFormat.parse(m_dg1.getDateOfExpiry());
                    Date birthday = dtFormat.parse(m_dg1.getDateOfBirth());
                    Date dnieTest = DateHelper.getExpeditionDate(birthday, expiryDate);
                    String strDate = dtFormat.format(dnieTest);
                    tvloc.setText(strDate);
                } catch (ParseException e) {
                    e.printStackTrace();
                }
                // Fecha de nacimiento
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_07);
                tvloc.setText(m_dg1.getDateOfBirth());
                // País de nacimiento
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_09);
                tvloc.setText(m_dg1.getNationality().toUpperCase());
            }

            ////////////////////////////////////////////////////////////////////////
            // Información del DG11, si la tenemos
            if(m_dg11!=null) {
                // Lugar de nacimiento
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_08);
                tvloc.setText(m_dg11.getBirthPlace().replace("<", " (") + ")");
                // DNIe Number
                tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_03);
                tvloc.setText(m_dg11.getPersonalNumber());
                try {
                    String[] address = m_dg11.getAddress(0).split("<");
                    // Dirección actual
                    tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_04);
                    tvloc.setText(address[0]);

                    // Provincia
                    if (address.length >= 3) {
                        tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_05);
                        //tvloc.setText(m_dg11.getAddress(DG11.ADDR_PROVINCIA));
                        tvloc.setText(address[2]);
                    }
                    // Localidad
                    tvloc = (TextView) findViewById(R.id.CITIZEN_data_tab_06);
                    tvloc.setText(address[1]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    e.printStackTrace();
                }
            }

            ////////////////////////////////////////////////////////////////////////
            // Información del DG2 (foto), si la tenemos
            ImageView ivFoto = (ImageView) findViewById(R.id.CITIZEN_data_tab_00);
            if(m_dataDG2!=null){
                try {
                    // Parseo de la foto en formato JPEG-2000
                    byte [] imagen = m_dg2.getImageBytes();
                    J2kStreamDecoder j2k = new J2kStreamDecoder();
                    ByteArrayInputStream bis = new ByteArrayInputStream(imagen);
                    mLoadedImage = j2k.decode(bis);
                }catch(Exception e)
                {
                    e.printStackTrace();
                }
            }

            // Mostramos la foto si hemos podido decodificarla
            if(mLoadedImage !=null)
                ivFoto.setImageBitmap(mLoadedImage);
            else
                ivFoto.setImageResource(R.drawable.noface);

            ////////////////////////////////////////////////////////////////////////
            // Información del DG7, si la tenemos
            ImageView ivFirma = (ImageView) findViewById(R.id.CITIZEN_data_tab_00_SIGNATURE);
            if(m_dataDG7!=null){
                try {
                    // Parseo de la firma en formato JPEG-2000
                    byte [] imagen = m_dg7.getImageBytes();
                    J2kStreamDecoder j2k = new J2kStreamDecoder();
                    ByteArrayInputStream bis = new ByteArrayInputStream(imagen);
                    mLoadedSignature = j2k.decode(bis);
                }catch(Exception e)
                {
                    e.printStackTrace();
                }

                // Mostramos la firma si hemos podido decodificarla
                if(mLoadedSignature !=null) {
                    // Mostramos la firma
                    ivFirma.setVisibility(ImageView.VISIBLE);
                    ivFirma.setImageBitmap(mLoadedSignature);
                }
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////
        mButtonBack = findViewById(R.id.btnBack);
        mButtonStartRead = findViewById(R.id.btnValidate);

        mButtonBack.setOnClickListener(this);
        mButtonStartRead.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnBack) {
            Intent intent = new Intent(DNIeResultActivity.this, ReadModeActivity.class);
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
        final private DNIeResultActivity mActivity;
        private int mOperationResult;


        RPCCreatePartner(DNIeResultActivity activity, JSONRPCClientOdoo client) {
            mClient = client;
            mActivity = activity;
        }


        @Override
        public void run() {
            String name = mActivity.m_dg1.getSurname() + "  " + mActivity.m_dg1.getName();
            String docNumber = mActivity.m_dg11.getPersonalNumber();
            String sex = mActivity.m_dg1.getSex();
            String nation = mActivity.m_dg1.getNationality();
            String profession = mActivity.m_dg11.getProfession();
            String otherInfo = mActivity.m_dg11.getOtherInfo();
            String summary = mActivity.m_dg11.getSummary();
            String custodyInfo = mActivity.m_dg11.getCustodyInfo();
            String icaoName = mActivity.m_dg11.getIcaoName();
            Date expiryDate = null;
            Date birthday = null;
            try {
                DateFormat dtDNIFormat = DateFormat.getDateInstance(2);
                expiryDate = dtDNIFormat.parse(mActivity.m_dg1.getDateOfExpiry());
                birthday = dtDNIFormat.parse(mActivity.m_dg1.getDateOfBirth());
            } catch (ParseException e) {
                e.printStackTrace();
            }

            DateFormat dtFormat = new SimpleDateFormat("YYYY-MM-dd");
            Date dnieTest = DateHelper.getExpeditionDate(birthday, expiryDate);
            String strExpDate = dtFormat.format(dnieTest);
            String strBirthDate = dtFormat.format(birthday);

            try {
                Integer codeIneId = 0;
                String[] address = mActivity.m_dg11.getAddress(0).split("<");
                if (address.length == 3) {
                    JSONArray searchResult = mClient.callSearch("code.ine", String.format("[['name', '=ilike', '%s%c']]", mActivity.m_dg11.getAddress(0).split("<")[2], '%'), "['id', 'code', 'display_name']");
                    if (null != searchResult) {
                        codeIneId = searchResult.getJSONObject(0).getInt("id");
                    }
                }


                ByteArrayOutputStream byteArrayOS = new ByteArrayOutputStream();
                mActivity.mLoadedImage.compress(Bitmap.CompressFormat.JPEG, 90, byteArrayOS);
                String encodedPhoto = Base64.encodeToString(byteArrayOS.toByteArray(), Base64.NO_WRAP);


                String values = String.format("{'name': '%s', 'image': '%s', 'document_number': '%s', 'birthdate_date': '%s', 'gender': '%s', 'document_expedition_date': '%s', 'code_ine_id': %d, comment: 'Nation: %s'}", name, encodedPhoto, docNumber, strBirthDate, sex, strExpDate, codeIneId, nation);
                mOperationResult = mClient.callCreate("res.partner", values);

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
                e.printStackTrace();
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
    }
}
