package de.uni_bonn.bit.wallet_protocol;

import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.BCParameters;
import de.uni_bonn.bit.PaillierKeyPair;
import org.spongycastle.math.ec.ECPoint;

/**
 * The class defines a data transfer object and is used to transfer several setup parameters for the signature protocol.
 */
public class PairingMessage {
    PaillierKeyPair pkp;
    byte[] otherPublicKey;
    BCParameters bcParameters;

    private PairingMessage(){ }

    public PairingMessage(ECPoint otherPublicKey, PaillierKeyPair pkp, BCParameters bcParameters) {
        this.pkp = pkp;
        this.otherPublicKey = otherPublicKey.normalize().getEncoded(true);
        this.bcParameters = bcParameters;
    }

    public ECPoint getOtherPublicKey() {
        return ECKey.CURVE.getCurve().decodePoint(otherPublicKey);
    }

    public PaillierKeyPair getPkp() {
        return pkp;
    }

    public BCParameters getBcParameters() {
        return bcParameters;
    }
}
