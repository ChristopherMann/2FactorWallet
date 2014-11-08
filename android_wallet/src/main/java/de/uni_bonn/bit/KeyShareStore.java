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
package de.uni_bonn.bit;

import android.os.Parcel;
import android.os.Parcelable;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.params.RegTestParams;
import org.apache.avro.io.BinaryDecoder;
import org.apache.avro.io.DecoderFactory;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.reflect.AvroIgnore;
import org.apache.avro.reflect.ReflectDatumReader;
import org.apache.avro.reflect.ReflectDatumWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * This class stores the keys and parameters used by the two-party signature protocol. It is persisted with the help of
 * avro, but it also implements {@link android.os.Parcelable} as it is also used to pass around the parameters between
 * the different activities.
 */
public class KeyShareStore implements Parcelable {

    private byte[] privateKey;
    private byte[] otherPublicKey;
    private PaillierKeyPair pkpDesktop;
    private PaillierKeyPair pkpPhone;
    private BCParameters desktopBCParameters;
    private BCParameters phoneBCParameters;

    @AvroIgnore
    Address address;

    public KeyShareStore(ECKey privateKey, ECKey otherPublicKey, PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                         BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.privateKey = privateKey.getPrivKeyBytes();
        this.otherPublicKey = otherPublicKey.getPubKey();
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
    }

    private KeyShareStore(){

    }

    public ECKey getPrivateKey() {
        return ECKey.fromPrivate(privateKey);
    }

    public ECKey getOtherPublicKey() {
        return ECKey.fromPublicOnly(otherPublicKey);
    }

    public PaillierKeyPair getPkpDesktop() {
        return pkpDesktop;
    }

    public PaillierKeyPair getPkpPhone() {
        return pkpPhone;
    }

    public BCParameters getDesktopBCParameters() {
        return desktopBCParameters;
    }

    public BCParameters getPhoneBCParameters() { return phoneBCParameters; }

    //---Parcelable serialization code ---
    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByteArray(privateKey);
        dest.writeByteArray(otherPublicKey);
        dest.writeByteArray(serialize(pkpDesktop));
        dest.writeByteArray(serialize(pkpPhone));
        dest.writeByteArray(serialize(desktopBCParameters));
        dest.writeByteArray(serialize(phoneBCParameters));
    }

    @AvroIgnore
    public static final Parcelable.Creator<KeyShareStore> CREATOR
            = new Parcelable.Creator<KeyShareStore>() {
        public KeyShareStore createFromParcel(Parcel in) {
            return new KeyShareStore(in);
        }

        public KeyShareStore[] newArray(int size) {
            return new KeyShareStore[size];
        }
    };

    private KeyShareStore(Parcel in) {
        privateKey = in.createByteArray();
        otherPublicKey = in.createByteArray();
        pkpDesktop = (PaillierKeyPair) deserialize(in.createByteArray(), PaillierKeyPair.class);
        pkpPhone = (PaillierKeyPair) deserialize(in.createByteArray(), PaillierKeyPair.class);
        desktopBCParameters = (BCParameters) deserialize(in.createByteArray(), BCParameters.class);
        phoneBCParameters = (BCParameters) deserialize(in.createByteArray(), BCParameters.class);
    }

    private static byte[] serialize(Object obj){
        try{
            ReflectDatumWriter writer = new ReflectDatumWriter<>(obj.getClass());
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            Encoder encoder = EncoderFactory.get().binaryEncoder(bout, null);
            writer.write(obj, encoder);
            encoder.flush();
            return bout.toByteArray();
        }catch(IOException e){
            return null;
        }
    }

    private Object deserialize(byte[] data, Class<?> clazz){
        try{
            ReflectDatumReader datumReader = new ReflectDatumReader<>(clazz);
            BinaryDecoder decoder = DecoderFactory.get().binaryDecoder(data, null);
            return datumReader.read(null, decoder);
        }catch(IOException e){
            return null;
        }
    }


    public String getAddressAsString() {
        if(address == null){
            address = BitcoinECMathHelper.convertPointToPubKEy(
                    BitcoinECMathHelper.convertPubKeyToPoint(getOtherPublicKey())
                            .multiply(BitcoinECMathHelper.convertPrivKeyToBigInt(getPrivateKey())
                            )).toAddress(RegTestParams.get());
        }
        return address.toString();
    }
}
