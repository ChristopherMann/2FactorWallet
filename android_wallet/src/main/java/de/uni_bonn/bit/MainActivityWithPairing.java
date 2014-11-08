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
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.reflect.ReflectDatumReader;
import org.apache.avro.reflect.ReflectDatumWriter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * This is the main activity for the phone wallet. It is displayed when the phone wallet is started. It is
 * responsible for the loading the persisted {@link de.uni_bonn.bit.KeyShareStore} with the keys and parameters for the
 * two-party signature protocol. If no {@link de.uni_bonn.bit.KeyShareStore} is found, this activity forces the user
 * to execute the pairing protocol first.
 */
public class MainActivityWithPairing extends Activity {

    KeyShareStore keyShareStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_activity_with_pairing);
        findViewById(R.id.addressLayout).setVisibility(View.INVISIBLE);
        try {
            FileInputStream inputStream = openFileInput("wallet.bin");
            ReflectDatumReader<KeyShareStore> datumReader = new ReflectDatumReader<>(KeyShareStore.class);
            BinaryDecoder decoder = DecoderFactory.get().binaryDecoder(inputStream,null);
            keyShareStore = datumReader.read(null, decoder);
            ((TextView) findViewById(R.id.txtInfo)).setText(R.string.info_text_paired);
            ((TextView) findViewById(R.id.txtAddress)).setText(keyShareStore.getAddressAsString());
            findViewById(R.id.addressLayout).setVisibility(View.VISIBLE);
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main_activity_with_pairing, menu);
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

    @Override
    protected void onPause() {
        super.onPause();
        if(keyShareStore != null){
            try {
                FileOutputStream outputStream = openFileOutput("wallet.bin", MODE_PRIVATE);
                ReflectDatumWriter<KeyShareStore> specificDatumWriter = new ReflectDatumWriter<>(KeyShareStore.class);
                Encoder encoder = EncoderFactory.get().binaryEncoder(outputStream, null);
                specificDatumWriter.write(keyShareStore, encoder);
                encoder.flush();
                outputStream.flush();
                outputStream.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void onBtnPairUnpairClicked(View view){
        startActivityForResult(new Intent(this, PairingActivity.class), 1000);
    }

    public void onBtnSignTransactionClicked(View view){
        Intent intent = new Intent(this, TransactionConfirmActivity.class);
        intent.putExtra("KeyShareStore", keyShareStore);
        startActivity(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(requestCode == 1000){
            if(resultCode == RESULT_OK){
                String address = data.getExtras().getString("ADDRESS");
                keyShareStore = data.getExtras().getParcelable("KeyShareStore");
                TextView txtInfo = (TextView) findViewById(R.id.txtInfo);
                txtInfo.setText(R.string.info_text_paired);
                ((TextView) findViewById(R.id.txtAddress)).setText(keyShareStore.getAddressAsString());
                findViewById(R.id.addressLayout).setVisibility(View.VISIBLE);
            }else{
                TextView txtInfo = (TextView) findViewById(R.id.txtInfo);
                txtInfo.setText(R.string.info_text_paring_failed + R.string.info_text_not_paired);
            }
        }

    }
}
