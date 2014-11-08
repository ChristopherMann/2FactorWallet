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

import org.bitcoinj.core.Base58;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import de.uni_bonn.bit.wallet_protocol.QRCodeData;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.reflect.ReflectDatumWriter;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;


/**
 * This class contains some helper methods to create a QRCode which contains some given data.
 */
public class QRCodeHelper {

    /**
     * This methods creates a QRCode which contains a list of IP addresses and a public key for a TLS connection. The
     * data is serialized with avro and then Base58 encoded. The resulting string is then stored inside the QR code which
     * is returned as a {@link java.awt.image.BufferedImage}.
     */
    public static BufferedImage CreateQRCodeForTLSSetup(List<String> ipAddresses, PublicKey publicKey) throws IOException, WriterException {
        ReflectDatumWriter<QRCodeData> specificDatumWriter = new ReflectDatumWriter<>(QRCodeData.class);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        Encoder encoder = EncoderFactory.get().binaryEncoder(bout, null);
        QRCodeData data = new QRCodeData(
                IPAddressHelper.getAllUsableIPAddresses(),
                publicKey
        );
        specificDatumWriter.write(data, encoder);
        encoder.flush();
        bout.flush();
        return CreateQRCodeFromString(Base58.encode(bout.toByteArray()));
    }

    public static BufferedImage CreateQRCodeFromString(String string) throws WriterException {
        return MatrixToImageWriter
                .toBufferedImage(new MultiFormatWriter().encode(
                        string,
                        BarcodeFormat.QR_CODE, 200, 200
                ));
    }
}
