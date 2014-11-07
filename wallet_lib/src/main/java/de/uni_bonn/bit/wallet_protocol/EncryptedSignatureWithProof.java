package de.uni_bonn.bit.wallet_protocol;

import org.apache.avro.reflect.Stringable;

import java.math.BigInteger;

/**
 * This class defines data transfer object and represents the last message in the signature protocol. It contains the
 * encrypted signature and a zero-knowledge proof.
 */
public class EncryptedSignatureWithProof {

    @Stringable
    public BigInteger sigma;
    @Stringable
    public BigInteger alphaPrime;
    public ZKProofPhone proof;

    public EncryptedSignatureWithProof(){}

    public EncryptedSignatureWithProof(BigInteger sigma, BigInteger alphaPrime, ZKProofPhone proof) {
        this.sigma = sigma;
        this.alphaPrime = alphaPrime;
        this.proof = proof;
    }
}
