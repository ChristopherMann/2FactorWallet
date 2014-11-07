package de.uni_bonn.bit.wallet_protocol;

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

/**
 * This class defines data transfer object and represents the second message of the signature protocol. It contains a
 * public ephemeral value share.
 */
public class EphemeralValueShare {
    private byte[] Q2;


    private EphemeralValueShare(){ }

    public EphemeralValueShare(ECPoint Q2){
        setQ2(Q2);
    }

    public ECPoint getQ2() {
        return ECKey.CURVE.getCurve().decodePoint(this.Q2);
    }

    public void setQ2(ECPoint Q2) {
        this.Q2 = Q2.getEncoded(true);
    }
}
