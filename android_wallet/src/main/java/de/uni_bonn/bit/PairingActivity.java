package de.uni_bonn.bit;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import de.uni_bonn.bit.wallet_protocol.IPairingProtocol;
import de.uni_bonn.bit.wallet_protocol.PairingMessage;
import de.uni_bonn.bit.wallet_protocol.QRCodeData;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.ipc.NettyTransceiver;
import org.apache.avro.ipc.reflect.ReflectRequestor;
import org.apache.avro.reflect.ReflectDatumReader;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;

/**
 * This activity is displayed when pairing the phone wallet with a desktop wallet. In the beginning, it asks the user
 * to scan a QR code to retrieve the information on the server to connect to. It then connects to the server and
 * execute the pairing protocol. Afterwards, it displays the Bitcoin address, which is now under shared control of the
 * two wallets.
 */
public class PairingActivity extends Activity {

    private KeyShareStore keyShareStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pairing);
        findViewById(R.id.addressLayout).setVisibility(View.INVISIBLE);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.pairing, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void onBtnScanPairingCodeClicked(View view){
        new IntentIntegrator(this).initiateScan(IntentIntegrator.QR_CODE_TYPES);
    }

    public void onBtnCloseClicked(View view){
        Intent intent = new Intent();
        intent.putExtra("KeyShareStore", keyShareStore);
        setResult(RESULT_OK, intent);
        finish();
    }

    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        final TextView txtInfo = (TextView)findViewById(R.id.txtInfo);
        final IntentResult scanResult = IntentIntegrator.parseActivityResult(
                requestCode, resultCode, intent);
        if (scanResult != null) {
            txtInfo.append("\nPairing code successfully scanned.");
            txtInfo.append("\nStarting pairing protocol...");
            new AsyncTask<String, Void, KeyShareStore>(){
                private Exception exception;
                @Override protected KeyShareStore doInBackground(String... params) {
                    try {
                        byte[] bytes = Base58.decode(params[0]);
                        ReflectDatumReader<QRCodeData> datumReader = new ReflectDatumReader<>(QRCodeData.class);
                        BinaryDecoder decoder = DecoderFactory.get().binaryDecoder(bytes, null);
                        QRCodeData qrCodeData = datumReader.read(null, decoder);
                        NettyTransceiver client = TLSClientHelper.createNettyTransceiver(
                                qrCodeData.getPublicKey(), qrCodeData.getIpAddresses());
                        IPairingProtocol clientProxy = ReflectRequestor.getClient(IPairingProtocol.class, client);

                        BigInteger keyShare = IntegerFunctions.randomize(ECKey.CURVE.getN());
                        ECPoint sharePublicKey = ECKey.CURVE.getG().multiply(keyShare).normalize();
                        PaillierKeyPair pkp = PaillierKeyPair.generatePaillierKeyPair();
                        BCParameters phoneBCParameters = BCParameters.generateBCParameters2();
                        PairingMessage message = new PairingMessage(sharePublicKey, pkp, phoneBCParameters);
                        PairingMessage response = clientProxy.pair(message);
                        KeyShareStore keyShareStore = new KeyShareStore(BitcoinECMathHelper.convertBigIntToPrivKey(keyShare),
                                BitcoinECMathHelper.convertPointToPubKEy(response.getOtherPublicKey()),
                                response.getPkp(), pkp, response.getBcParameters(), phoneBCParameters);
                        return keyShareStore;
                    } catch (Exception e) {
                        exception = e;
                    }
                    return null;
                }

                @Override protected void onPostExecute(KeyShareStore keyShareStore) {
                    if(keyShareStore != null){
                        PairingActivity.this.keyShareStore = keyShareStore;
                        txtInfo.append("\nPairing protocol successfully completed. Please verify that desktop and phone have agreed on the same address.");
                        findViewById(R.id.addressLayout).setVisibility(View.VISIBLE);
                        ((TextView) findViewById(R.id.txtAddress)).setText(keyShareStore.getAddressAsString());
                    }else{
                        txtInfo.setText("\nException occured during the paring protocol:\n" + exception.getMessage()
                                + "\n\n Please try again.");
                    }

                }
            }.execute(scanResult.getContents());
        }else{
            txtInfo.setText("\nScanning of the pairing code failed. Please try again");
        }
    }

}
