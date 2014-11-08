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

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.core.WalletExtension;
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
 * A {@link org.bitcoinj.core.WalletExtension} which stores the keys and parameters for the two-factor wallet.
 * The contents of this class are stored on the disk as part of the serialization of the {@link org.bitcoinj.core.Wallet}.
 */
public class KeyShareWalletExtension implements WalletExtension {

    private byte[] privateKey;
    private byte[] otherPublicKey;
    private PaillierKeyPair pkpDesktop;
    private PaillierKeyPair pkpPhone;
    private BCParameters desktopBCParameters;
    private BCParameters phoneBCParameters;

    @AvroIgnore
    private Address address;

    @Override
    public String getWalletExtensionID() {
        return "de.uni_bonn.bit.KeyShareWalletExtension";
    }

    @Override
    public boolean isWalletExtensionMandatory() {
        return false;
    }

    @Override
    public byte[] serializeWalletExtension() {
        ReflectDatumWriter<KeyShareWalletExtension> specificDatumWriter = new ReflectDatumWriter<>(KeyShareWalletExtension.class);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        Encoder encoder = EncoderFactory.get().binaryEncoder(bout, null);
        try {
            specificDatumWriter.write(this, encoder);
            encoder.flush();
            bout.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bout.toByteArray();
    }

    @Override
    public void deserializeWalletExtension(Wallet containingWallet, byte[] data) throws Exception {
        ReflectDatumReader<KeyShareWalletExtension> datumReader = new ReflectDatumReader<>(KeyShareWalletExtension.class);
        BinaryDecoder decoder = DecoderFactory.get().binaryDecoder(data, null);
        KeyShareWalletExtension result = datumReader.read(null, decoder);
        this.privateKey = result.privateKey;
        this.otherPublicKey = result.otherPublicKey;
        this.pkpDesktop = result.pkpDesktop;
        this.pkpPhone = result.pkpPhone;
        this.desktopBCParameters = result.desktopBCParameters;
        this.phoneBCParameters = result.phoneBCParameters;
    }

    public ECKey getPrivateKey(){
        return ECKey.fromPrivate(privateKey);
    }

    public ECKey getOtherPublicKey(){
        return ECKey.fromPublicOnly(otherPublicKey);
    }

    public PaillierKeyPair getPkpDesktop(){
        return pkpDesktop;
    }

    public PaillierKeyPair getPkpPhone(){
        return pkpPhone;
    }

    public BCParameters getDesktopBCParameters(){
        return desktopBCParameters;
    }

    public BCParameters getPhoneBCParameters(){
        return phoneBCParameters;
    }

    public void setPrivateKey(ECKey privateKey) {
        this.privateKey = privateKey.getPrivKeyBytes();
    }

    public void setOtherPublicKey(ECKey otherPublicKey) {
        this.otherPublicKey = otherPublicKey.getPubKey();
    }

    public void setPkpDesktop(PaillierKeyPair pkpDesktop) {
        this.pkpDesktop = pkpDesktop;
    }

    public void setPkpPhone(PaillierKeyPair pkpPhone) {
        this.pkpPhone = pkpPhone;
    }

    public void setDesktopBCParameters(BCParameters desktopBCParameters) {
        this.desktopBCParameters = desktopBCParameters;
    }

    public void setPhoneBCParameters(BCParameters phoneBCParameters) {
        this.phoneBCParameters = phoneBCParameters;
    }

    public String getAddressAsString(){
        return getAddress().toString();
    }

    public Address getAddress(){
        if(address == null){
            address = BitcoinECMathHelper.convertPointToPubKEy(
                    BitcoinECMathHelper.convertPubKeyToPoint(getOtherPublicKey())
                            .multiply(BitcoinECMathHelper.convertPrivKeyToBigInt(getPrivateKey())
                            )).toAddress(RegTestParams.get());
        }
        return address;
    }
}
