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
