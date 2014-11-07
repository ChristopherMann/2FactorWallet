package de.uni_bonn.bit.wallet_protocol;

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

/**
 * This class defines data transfer object and represents the third message of the signature protocol. It contains the
 * public ephemeral value and a zero-knowledge proof.
 */
public class EphemeralPublicValueWithProof {
    private byte[] Q;
    private ZKProofDesktop proof;

    private EphemeralPublicValueWithProof(){ }

    public EphemeralPublicValueWithProof(ECPoint Q, ZKProofDesktop proof) {
        this.Q = Q.getEncoded(true);
        this.proof = proof;
    }

    public ECPoint getQ() {
        return ECKey.CURVE.getCurve().decodePoint(this.Q);
    }

    public ZKProofDesktop getProof() {
        return proof;
    }
}
