package de.uni_bonn.bit.wallet_protocol;

import org.apache.avro.reflect.Stringable;

import java.math.BigInteger;

/**
 * This class defines data transfer object and represents the first message of the signature protocol. It contains the
 * encrypted signature parts.
 */
public class SignatureParts {

    @Stringable
    BigInteger alpha;
    @Stringable
    BigInteger beta;

    public SignatureParts() {}
    public SignatureParts(BigInteger alpha, BigInteger beta) {
        this.alpha = alpha;
        this.beta = beta;
    }

    public BigInteger getAlpha() {
        return alpha;
    }

    public void setAlpha(BigInteger alpha) {
        this.alpha = alpha;
    }

    public BigInteger getBeta() {
        return beta;
    }

    public void setBeta(BigInteger beta) {
        this.beta = beta;
    }
}
