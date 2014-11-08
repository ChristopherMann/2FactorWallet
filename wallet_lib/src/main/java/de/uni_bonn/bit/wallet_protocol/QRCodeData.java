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
package de.uni_bonn.bit.wallet_protocol;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

/**
 * This class defines a data transfer object which contains the data which should be transferred from the desktop to
 * the phone with the help of a QR code. It contains the IP addresses of the desktop and the desktop's public key for
 * a TLS connection.
 */
public class QRCodeData{
    List<String> ipAddresses;
    byte[] publicKey;

    public QRCodeData() {} //for serialization

    public QRCodeData(List<String> ipAddresses, PublicKey publicKey) {
        this.ipAddresses = ipAddresses;
        setPublicKey(publicKey);
    }

    public List<String> getIpAddresses() {
        return ipAddresses;
    }

    public void setIpAddresses(List<String> ipAddresses) {
        this.ipAddresses = ipAddresses;
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(this.publicKey));
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey.getEncoded();
    }
}
