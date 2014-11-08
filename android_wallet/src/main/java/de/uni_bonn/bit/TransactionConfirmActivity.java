/*
* Copyright 2014 Christopher Mann
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package de.uni_bonn.bit;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import org.bitcoinj.core.*;
import org.bitcoinj.params.RegTestParams;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import de.uni_bonn.bit.wallet_protocol.*;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.ipc.NettyTransceiver;
import org.apache.avro.ipc.reflect.ReflectRequestor;
import org.apache.avro.reflect.ReflectDatumReader;

import java.util.ArrayList;
import java.util.List;

/**
 * This transaction is used to sign a transaction on phone. In the beginning, it asks the user
 * to scan a QR code to retrieve the information on the server to connect to. It then connects to the server and
 * retrieves the transaction to sign. The transaction is displayed to the user for review. If the user confirms the
 * transaction, this activity connects to the server again and executes the two-party signature protocol.
 */
public class TransactionConfirmActivity extends Activity {

    protected TransactionInfo transactionInfo;
    protected IWalletProtocol clientProxy;
    protected NettyTransceiver client;
    protected KeyShareStore keyShareStore;
    protected ECKey privateKey;
    protected ECKey otherPublicKey;
    protected PaillierKeyPair pkpDesktop;
    protected PaillierKeyPair pkpPhone;
    protected BCParameters bcParameters;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_transaction_confirm);
        keyShareStore = getIntent().getExtras().getParcelable("KeyShareStore");
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.transaction_confirm, menu);
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

    public void onBtnScanTransactionClicked(View view){
        new IntentIntegrator(this).initiateScan(IntentIntegrator.QR_CODE_TYPES);
    }

    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        final TextView txtInfo = (TextView)findViewById(R.id.txtInfo);
        final IntentResult scanResult = IntentIntegrator.parseActivityResult(
                requestCode, resultCode, intent);
        if (scanResult != null) {
            new AsyncTask<String, Void, TransactionInfo>(){
                private Exception exception;
                @Override protected TransactionInfo doInBackground(String... params) {
                    try {
                        byte[] bytes = Base58.decode(params[0]);
                        ReflectDatumReader<QRCodeData> datumReader = new ReflectDatumReader<>(QRCodeData.class);
                        BinaryDecoder decoder = DecoderFactory.get().binaryDecoder(bytes, null);
                        QRCodeData qrCodeData = datumReader.read(null, decoder);
                        client = TLSClientHelper.createNettyTransceiver(qrCodeData.getPublicKey(), qrCodeData.getIpAddresses());
                        clientProxy = ReflectRequestor.getClient(IWalletProtocol.class, client);
                        TransactionInfo txInfo = clientProxy.fetchTransactionInfo();
                        return txInfo;
                    } catch (Exception e) {
                        exception = e;
                    }
                    return null;
                }

                @Override protected void onPostExecute(TransactionInfo transactionInfo) {
                    if(transactionInfo != null){
                        TransactionConfirmActivity.this.transactionInfo = transactionInfo;
                        txtInfo.setText("Transaction received. Please verify the transaction and confirm it.");
                        ListView outputsListView = (ListView) findViewById(R.id.outputsListView);
                        List<String> outputList = new ArrayList<>();
                        for(TransactionOutput txOutput : transactionInfo.getTransaction().getOutputs()){
                            String addressString = txOutput.getScriptPubKey().getToAddress(RegTestParams.get()).toString();
                            if(addressString.equals(keyShareStore.getAddressAsString())){
                                addressString = "Change ("
                                        + addressString.substring(0,4)
                                        + "..."
                                        + addressString.substring(addressString.length() - 4 ,addressString.length())
                                        + ")";
                            }
                            outputList.add(addressString
                                + "\n\t" + txOutput.getValue().toFriendlyString() + " BTC");
                        }
                        Coin fee = computeFeeForTransactionInfo(transactionInfo);
                        outputList.add("Miner fee\n\t" + fee.toFriendlyString() + "BTC");
                                outputsListView.setAdapter(new ArrayAdapter(getApplicationContext(), R.layout.list_entry, outputList));
                    }else{
                        txtInfo.setText("Exception occured while fetching the transaction:\n" + exception.getMessage());
                    }
                }
            }.execute(scanResult.getContents());
        }else{
            txtInfo.setText("The transaction code could not be scanned. Please try again.");
        }
    }

    public void onBtnConfirmTransactionClicked(View view){
        final TextView txtInfo = (TextView)findViewById(R.id.txtInfo);
        if(transactionInfo != null)
            new AsyncTask<TransactionInfo, Integer, Transaction>() {
                private Exception exception;
                private long timeTaken;

                @Override
                protected Transaction doInBackground(TransactionInfo... params) {
                    try {
                        long startTime = System.currentTimeMillis();
                        publishProgress(0);
                        TransactionInfo transactionInfo = params[0];
                        Transaction transaction = transactionInfo.getTransaction();
                        PhoneTransactionSigner phoneSigner = new PhoneTransactionSigner(transactionInfo,
                                keyShareStore.getPrivateKey(),keyShareStore.getOtherPublicKey(),
                                keyShareStore.getPkpDesktop(), keyShareStore.getPkpPhone(), keyShareStore.getDesktopBCParameters(),
                                keyShareStore.getPhoneBCParameters());
                        SignatureParts[] signatureParts = clientProxy.getSignatureParts();
                        publishProgress(1);
                        EphemeralValueShare[] ephemeralValueShares = phoneSigner.generateEphemeralValueShare(signatureParts);
                        publishProgress(2);

                        EphemeralPublicValueWithProof[] ephemeralPublicValuesWithProof = clientProxy.getEphemeralPublicValuesWithProof(ephemeralValueShares);
                        publishProgress(3);
                        EncryptedSignatureWithProof[] encryptedSignaturesWithProof = phoneSigner.computeEncryptedSignatures(ephemeralPublicValuesWithProof);
                        publishProgress(4);
                        boolean result = clientProxy.sendEncryptedSignatures(encryptedSignaturesWithProof);
                        publishProgress(5);
                        long endTime = System.currentTimeMillis();
                        timeTaken = endTime - startTime;
                    } catch (Exception e) {
                        e.printStackTrace();
                        exception = e;
                    }
                    return null;

                }
                @Override protected void onPostExecute(Transaction transaction) {
                    if(exception != null){
                        txtInfo.setText("Exception occured while fetching the transaction:\n" + exception.getMessage());
                    }else{
                        txtInfo.setText("Phone has successfully completed the protocol. Time taken " + timeTaken + "ms");
                    }

                }

                @Override
                protected void onProgressUpdate(Integer... values) {
                    txtInfo.setText("Executing signing protocol: " + values[0] + "/5");
                }
            }.execute(transactionInfo);
    }

    private static Coin computeFeeForTransactionInfo(TransactionInfo transactionInfo){
        Coin result = Coin.ZERO;
        Transaction tx = transactionInfo.getTransaction();
        //add values of connected outputs
        for(int i = 0; i < tx.getInputs().size(); i++){
            TransactionInput txInput = tx.getInput(i);
            if(! txInput.getOutpoint().getHash().equals(transactionInfo.getConnectedTransactionsForInput(i).getHash())){
                throw new ProtocolException("Transaction input and provided connected transaction do not fit together!");
            }
            TransactionOutput connectedOutput = transactionInfo.getConnectedTransactionsForInput(i).getOutput(
                    (int) txInput.getOutpoint().getIndex());
            result = result.add(connectedOutput.getValue());
        }
        //substract spend values
        for(TransactionOutput txOutput : tx.getOutputs()){
            result = result.subtract(txOutput.getValue());
        }
        if(result.compareTo(Coin.ZERO) < 0){
            throw new ProtocolException("Transaction is spending more bitcoins than available by the inputs.");
        }
        return result;
    }


}
