package com.totp.android.twofactor;

import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.appindexing.Action;
import com.google.android.gms.appindexing.AppIndex;
import com.google.android.gms.common.api.GoogleApiClient;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.json.JSONObject;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final String SERVICE_URL = "http://192.168.1.34:8080/RestWebServiceDemo/rest/datos"; //Casa
    //private static final String SERVICE_URL = "http://192.168.1.85:8080/RestWebServiceDemo/rest/datos"; //Lab

    private static final String TAG = "MainActivity";
    private TextView textViewResultado;
    private GoogleApiClient client;

    NfcAdapter nfcAdapter;

    private TextView textViewInfo; //Muestra status word de la respuesta al primer apdu
    private TextView textViewInfo2; //Muestra status word de la respuesta al segundo apdu
    private TextView textViewData; //Muestra los datos de respuesta

    protected static final int TIMER_RUNTIME = 30000;
    protected boolean mbActive;
    protected ProgressBar mProgressBar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);

        //Barra de progreso de 30 segundos
        mProgressBar = (ProgressBar)findViewById(R.id.barra);

        final Thread timerThread = new Thread(){
            @Override
            public void run() {
                mbActive = true;
                try{

                    Date date = new Date();
                    long milisec = date.getTime(); //Devuelve el tiempo actual en milisegundos desde 1970

                    long periodos = milisec / TIMER_RUNTIME; //Dividirlo en periodos de 30 segundos
                    long inicio = periodos * TIMER_RUNTIME; //Segunods del inicio del periodo en el que está
                    long progresobarra=(milisec-inicio); //Instante en el periodo en el que está
                    int progreso= (int) progresobarra;

                    while(mbActive && (progreso < TIMER_RUNTIME)){
                        sleep(200);
                        if (mbActive){
                            progreso += 200;
                            updateProgess(progreso); //actualizar la barra de progreso
                        }
                    }

                }catch (InterruptedException e){
                    //caso error
                }finally{
                    run();
                }
            }
        };
        timerThread.start();


        // Comprobar adaptador NFC
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            Toast.makeText(this, "NFC DISPONIBLE", Toast.LENGTH_LONG).show();
        } else {
            finish();
        }

        // ATTENTION: This was auto-generated to implement the App Indexing API.
        client = new GoogleApiClient.Builder(this).addApi(AppIndex.API).build();

        textViewResultado=(TextView) findViewById(R.id.textViewResultado);
        textViewInfo = (TextView) findViewById(R.id.info);
        textViewInfo2 = (TextView) findViewById(R.id.info2);
        textViewData = (TextView) findViewById(R.id.data);

    }

    //Avance de la barra de progreso
    public void updateProgess(final int timePassed){
        if(null != mProgressBar){

            final int progress = mProgressBar.getMax() * timePassed / TIMER_RUNTIME;
            mProgressBar.setProgress(progress);
        }
    }


    //Envio y recepcion de APDUs mediante NFC
    @Override
    protected void onNewIntent(Intent intent) {

        //Toast.makeText(this, "NFC intent recibido", Toast.LENGTH_SHORT).show();

        byte[] SELECT = {
                (byte) 0x00, // CLA Class
                (byte) 0xA4, // INS Instruction
                (byte) 0x04, // P1  Parameter 1
                (byte) 0x00, // P2  Parameter 2
                (byte) 0x09, // Length
                (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x00, // AID del applet
                //(byte) 0xF1,(byte) 0xF2,(byte) 0xF3,(byte) 0xF4,(byte) 0xF5,(byte) 0xF6,(byte) 0xF7,(byte) 0xF8,(byte) 0xF9,(byte) 0x01,
        };


        byte[] tempo = hexStr2Bytes(tiempo());
        byte[] TIME = {
                (byte) 0x00, // CLA Class
                (byte) 0x50, // INS Instruction
                (byte) 0x00, // P1  Parameter 1
                (byte) 0x00, // P2  Parameter 2
                (byte) 0x08, // Length
                //(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x35, (byte) 0x35, (byte) 0x35, //Tiempo fijo de prueba: 555
                tempo[0], tempo[1], tempo[2], tempo[3], tempo[4], tempo[5], tempo[6], tempo[7],//Tiempo actual
                (byte) 0x7F //Lc
        };

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        IsoDep isodep = IsoDep.get(tag);

        try {
            isodep.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (isodep.isConnected()) {

            try {

                isodep.setTimeout(3000); //Timeout para esperar a la tarjeta
                byte[] respuesta = isodep.transceive(SELECT); //Envio el command Select del applet

                //Status Word
                String sw1 = Integer.toHexString(respuesta[respuesta.length - 2] & 0xFF);
                String sw2 = Integer.toHexString(respuesta[respuesta.length - 1] & 0xFF);

                textViewInfo.setText("APDU SELECT (SW1-SW2): " + sw1 + " " + sw2);

            } catch (IOException e) {
                e.printStackTrace();
            }

            try {
                byte[] respuesta2 = isodep.transceive(TIME); //Envio el command APDU con INS=50 y con el tiempo actual

                int offset = respuesta2[respuesta2.length - 3] & 0xf; //Hay que quitar SW1 y SW2
                int binary =
                        ((respuesta2[offset] & 0x7f) << 24) | //se quita el bit de signo y se desplaza 24 posiciones
                                ((respuesta2[offset + 1] & 0xff) << 16) | // se desplaza 16 posiciones
                                ((respuesta2[offset + 2] & 0xff) << 8) | //se desplaza 8 posiciones
                                (respuesta2[offset + 3] & 0xff);

                //El resultado anterior es un número de 31 bits (el más significativo es 0 (se ha quitado).


                int codeDigits = Integer.decode("6").intValue();
                int otp = binary % DIGITS_POWER[codeDigits]; //Cálculo del módulo 10^(número de dígitos que usas (8 en mi caso))

                String result = Integer.toString(otp);
                while (result.length() < codeDigits) {
                    result = "0" + result;      //RESULTADO TOTP
                }


                textViewData.setText("TOTP: " + result); //Muestra el RESULTADO TOTP por pantalla

                postTOTP(result); //Envio del resultado TOTP al servidor

                //Status Word
                String sw12 = Integer.toHexString(respuesta2[respuesta2.length - 2] & 0xFF);
                String sw22 = Integer.toHexString(respuesta2[respuesta2.length - 1] & 0xFF);

                textViewInfo2.setText("ADPU GENERATE_TOTP (SW1-SW2): " + sw12 + " " + sw22);


            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        super.onNewIntent(intent);
    }


    //Envio con POST del TOTP generado por la tarjeta al servidor
    public void postTOTP(String imagen){

        Toast.makeText(this, "TOTP Enviado", Toast.LENGTH_LONG).show();

        WebServiceTask wst = new WebServiceTask(WebServiceTask.POST_TASK, this, "Validando...");
        wst.addNameValuePair("totpass", imagen);

        // the passed String is the URL we will POST to
        wst.execute(new String[]{SERVICE_URL});
    }

    @Override
    public void onResume() {

        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_RECEIVER_REPLACE_PENDING);

        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
        IntentFilter[] intentfilter = new IntentFilter[]{};

        nfcAdapter.enableForegroundDispatch(this, pendingIntent, intentfilter, null);

        super.onResume();
    }


    @Override
    public void onPause() {
        nfcAdapter.disableForegroundDispatch(this);
        super.onPause();
    }


    private String tiempo() { //Calculo del tiempo actual

        String hora = null;
        long T0 = 0;
        long X = 30; //Para generar intervalos de 30 segundos

        Date date = new Date();
        long milisec = date.getTime(); //Devuelve el tiempo actual en milisegundos desde 1970
        long testTime[] = {milisec / 1000L}; //Pasarlo a segundos

        for (int i = 0; i < testTime.length; i++) {
            long T = (testTime[i] - T0) / X;
            hora = Long.toHexString(T);
        }
        //String hora = "555"; //tiempo fijo de prueba
        while (hora.length() < 16) hora = "0" + hora;
        return hora;
    }


    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto:   the crypto algorithm (HmacSHA1, HmacSHA256,
     *                  HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text:     the message or text to be authenticated
     */
    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
                                   byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);

        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }


    //Convertir HEX string to Byte[]
    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        System.out.println(ret);
        return ret;
    }

    //Esto es para obtener el módulo 10^(los dígitos) porque
    // asi se obtiene el HOTP=(Numero_de_31_bits)% 10^(dígitos deseados)
    private static final int[] DIGITS_POWER
            // 0  1   2    3     4      5       6        7         8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};



    //CALCULO DEL TOTP DE MANERA LOCAL EN LA APLICACION MOVIL
    /**
     * key: clave secreta
     * time: tiempo actual
     * returndigits: numero de digitos del TOTP
     */
    public String generateTOTP() {
        //String key = "3132333435363738393031323334353637383930"; //SECRET KEY
        //byte[] key = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30}; //SECRET KEY en byte array

        //SECRET KEY PARA LA DEMO DE GMAIL:
        byte[] key = {0x29,0x12,(byte)0xF6,0x2D,0x78,(byte)0xE8,0x2B,(byte)0xD4,0x2D,0x6E,(byte)0xAE,(byte)0xAA,(byte)0xA5,0x13,0x4B,(byte)0xD7,0x41,0x54,0x32,0x23};

        String returnDigits = "6";
        String time = tiempo();

        return generateTOTP1(key, time, returnDigits, "HmacSHA1"); //Llamada a la funcion que genera el TOTP
    }


    /**
     * key: clave secreta
     * time: tiempo actual
     * returndigits: numero de digitos del TOTP
     * crypto: la funcion crypto a utilizar "HmacSHA1" en este caso
     */

    public String generateTOTP1(byte[] key, //el secret lo recibo ya en byte[]
                                String time,
                                String returnDigits,
                                String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        byte[] msg = hexStr2Bytes(time);
        byte[] hash = hmac_sha(crypto, key, msg);

        //Calculo del offset del valor del HMAC
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    //Para generar y mostrar el TOTP en pantalla
    //Llamado desde el Button de generar codigo
    public void genero(View v) {
        String codigototp = generateTOTP();

        //y lo mostramos en la pantalla
        textViewResultado.setText(codigototp);
    }


    //CLEAR: Borrar contenido escrito de los dos campos
    public void clearControls(View vw) {

        EditText edTotpass = (EditText) findViewById(R.id.eltotpass);
        edTotpass.setText("");
    }


    //POST: Enviar datos desde la app al servidor
    public void postData(View vw) {

        EditText edTotpass = (EditText) findViewById(R.id.eltotpass);
        String totpass = edTotpass.getText().toString();

        if (totpass.equals("")) { //Este campo no puede estar vacio
            Toast.makeText(this, "Introducir los datos requeridos", Toast.LENGTH_LONG).show();
            return;
        }

        WebServiceTask wst = new WebServiceTask(WebServiceTask.POST_TASK, this, "Validando...");
        wst.addNameValuePair("totpass", totpass);

        // the passed String is the URL we will POST to
        wst.execute(new String[]{SERVICE_URL});
    }


    //AUTOPOST: POST sin tener que poner el TOTP manualmente
    public void autoPostData(View vw) {

        WebServiceTask wst = new WebServiceTask(WebServiceTask.POST_TASK, this, "Validando...");
        wst.addNameValuePair("totpass", generateTOTP()); //Llamo directamente al metodo generateTOTP

        // the passed String is the URL we will POST to
        wst.execute(new String[]{SERVICE_URL});
    }


    public void handleResponse(String response) {

        EditText edTotpass = (EditText) findViewById(R.id.eltotpass);
        edTotpass.setText("");

        try {

            JSONObject jso = new JSONObject(response);
            String totpass = jso.getString("totpass");
            String respuesta = jso.getString("respuesta");

            //Mostramos el resultado por pantalla
            Toast toast = Toast.makeText(this, "Resultado: " + respuesta, Toast.LENGTH_LONG);
            toast.show();
        }

        catch (Exception e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
        }

    }


    //ESCONDER TECLADO
    private void hideKeyboard() {
        InputMethodManager inputManager = (InputMethodManager) MainActivity.this
                .getSystemService(Context.INPUT_METHOD_SERVICE);

        inputManager.hideSoftInputFromWindow(
                MainActivity.this.getCurrentFocus()
                        .getWindowToken(), InputMethodManager.HIDE_NOT_ALWAYS);
    }


    @Override
    public void onStart() {
        super.onStart();

        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        client.connect();
        Action viewAction = Action.newAction(
                Action.TYPE_VIEW, // TODO: choose an action type.
                "Main Page", // TODO: Define a title for the content shown.
                // TODO: If you have web page content that matches this app activity's content,
                // make sure this auto-generated web page URL is correct.
                // Otherwise, set the URL to null.
                Uri.parse("http://host/path"),
                // TODO: Make sure this auto-generated app URL is correct.
                Uri.parse("android-app://com.totp.android.twofactor/http/host/path")
        );
        AppIndex.AppIndexApi.start(client, viewAction);
    }

    @Override
    public void onStop() {
        super.onStop();

        // ATTENTION: This was auto-generated to implement the App Indexing API.
        // See https://g.co/AppIndexing/AndroidStudio for more information.
        Action viewAction = Action.newAction(
                Action.TYPE_VIEW, // TODO: choose an action type.
                "Main Page", // TODO: Define a title for the content shown.
                // TODO: If you have web page content that matches this app activity's content,
                // make sure this auto-generated web page URL is correct.
                // Otherwise, set the URL to null.
                Uri.parse("http://host/path"),
                // TODO: Make sure this auto-generated app URL is correct.
                Uri.parse("android-app://com.totp.android.twofactor/http/host/path")
        );
        AppIndex.AppIndexApi.end(client, viewAction);
        client.disconnect();
    }


    //WEB SERVICE TASK

    public class WebServiceTask extends AsyncTask<String, Integer, String> {

        public static final int POST_TASK = 1;
        public static final int GET_TASK = 2;

        private static final String TAG = "WebServiceTask";

        // connection timeout, in milliseconds (waiting to connect)
        private static final int CONN_TIMEOUT = 3000;

        // socket timeout, in milliseconds (waiting for data)
        private static final int SOCKET_TIMEOUT = 6000;

        private int taskType = GET_TASK;
        private Context mContext = null;
        private String processMessage = "Procesando...";

        private ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();

        private ProgressDialog pDlg = null;

        public WebServiceTask(int taskType, Context mContext, String processMessage) {

            this.taskType = taskType;
            this.mContext = mContext;
            this.processMessage = processMessage;
        }

        public void addNameValuePair(String name, String value) {

            params.add(new BasicNameValuePair(name, value));
        }

        private void showProgressDialog() {

            pDlg = new ProgressDialog(mContext);
            pDlg.setMessage(processMessage);
            pDlg.setProgressDrawable(mContext.getWallpaper());
            pDlg.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            pDlg.setCancelable(false);
            pDlg.show();
        }

        @Override
        protected void onPreExecute() {

            hideKeyboard();
            showProgressDialog();
        }

        protected String doInBackground(String... urls) {

            String url = urls[0];
            String result = "";
            HttpResponse response = doResponse(url);

            if (response == null) {
                return result;
            } else {

                try {
                    result = inputStreamToString(response.getEntity().getContent());

                } catch (IllegalStateException e) {
                    Log.e(TAG, e.getLocalizedMessage(), e);

                } catch (IOException e) {
                    Log.e(TAG, e.getLocalizedMessage(), e);
                }
            }
            return result;
        }


        @Override
        protected void onPostExecute(String response) {

            handleResponse(response);
            pDlg.dismiss();
        }


        // Establish connection and socket (data retrieval) timeouts
        private HttpParams getHttpParams() {

            HttpParams htpp = new BasicHttpParams();

            HttpConnectionParams.setConnectionTimeout(htpp, CONN_TIMEOUT);
            HttpConnectionParams.setSoTimeout(htpp, SOCKET_TIMEOUT);

            return htpp;
        }

        private HttpResponse doResponse(String url) {

            // Use our connection and data timeouts as parameters for our DefaultHttpClient
            HttpClient httpclient = new DefaultHttpClient(getHttpParams());
            HttpResponse response = null;

            try {
                switch (taskType) {

                    case POST_TASK:
                        HttpPost httppost = new HttpPost(url);
                        // Add parameters
                        httppost.setEntity(new UrlEncodedFormEntity(params));

                        response = httpclient.execute(httppost);
                        break;
                    case GET_TASK:
                        HttpGet httpget = new HttpGet(url);
                        response = httpclient.execute(httpget);
                        break;
                }
            } catch (Exception e) {

                Log.e(TAG, e.getLocalizedMessage(), e);
            }
            return response;
        }

        private String inputStreamToString(InputStream is) {

            String line = "";
            StringBuilder total = new StringBuilder();

            // Wrap a BufferedReader around the InputStream
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));

            try {
                // Read response until the end
                while ((line = rd.readLine()) != null) {
                    total.append(line);
                }
            } catch (IOException e) {
                Log.e(TAG, e.getLocalizedMessage(), e);
            }

            // Return full string
            return total.toString();
        }
    }
}
