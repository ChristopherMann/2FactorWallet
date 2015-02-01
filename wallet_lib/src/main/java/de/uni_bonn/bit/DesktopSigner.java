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

import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.wallet_protocol.*;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;
import java.util.concurrent.ForkJoinTask;

/**
 * This class implements the desktop's part of the two-party ECDSA signature protocol. The desktop takes the side of Alice
 * in the protocol. In the end, this class returns an ECDSA signature.
 */
public class DesktopSigner {

    static final BigInteger nEC = ECKey.CURVE.getN();
    PaillierKeyPair pkpDesktop;
    PaillierKeyPair pkpPhone;
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;
    BigInteger privateKey;
    ECPoint otherPublicKey;
    MultiThreadingHelper zkProofHelper;

    protected BigInteger kDesktop;
    protected BigInteger zDesktop;
    protected BigInteger r1;
    protected BigInteger alphaDesktop;
    protected BigInteger r2;
    protected BigInteger beta;

    protected ECPoint RPhone;
    protected ECPoint R;
    protected States state;

    public DesktopSigner(ECKey privateKey, ECKey otherPublicKey,  PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                         BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.privateKey = BitcoinECMathHelper.convertPrivKeyToBigInt(privateKey);
        this.otherPublicKey = BitcoinECMathHelper.convertPubKeyToPoint(otherPublicKey);
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.zkProofHelper = new MultiThreadingHelper();
        this.state = States.ComputeSignatureParts;
    }

    public SignatureParts computeSignatureParts(){
        if(! state.equals(States.ComputeSignatureParts))
            throw new ProtocolException("Operation not allowed in this protocol state.");
        kDesktop = IntegerFunctions.randomize(nEC);
        zDesktop = kDesktop.modInverse(nEC);
        r1 = pkpDesktop.generateRandomizer();
        r2 = pkpDesktop.generateRandomizer();
        BigInteger nsquaredDesktop = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> betaFuture = zkProofHelper.PowMult(pkpDesktop.getG(), privateKey.multiply(zDesktop).mod(nEC), r2, pkpDesktop.getN(), nsquaredDesktop);
        ForkJoinTask<BigInteger> alphaDesktopFuture = zkProofHelper.PowMult(pkpDesktop.getG(), zDesktop, r1, pkpDesktop.getN(), nsquaredDesktop);
        beta =  betaFuture.join();
        alphaDesktop = alphaDesktopFuture.join();
        state = States.ComputeEphemeralPublicValue;
        return new SignatureParts(alphaDesktop, beta);
    }

    public EphemeralPublicValueWithProof computeEphemeralPublicValue(EphemeralValueShare ephemeralValueShare){
        if(! state.equals(States.ComputeEphemeralPublicValue))
            throw new ProtocolException("Operation not allowed in this protocol state.");
        RPhone = ephemeralValueShare.getRPhone();
        // We first check that RPhone is associated with the correct curve and then we check that it is on the associated curve.
        if(! (RPhone.getCurve().equals(ECKey.CURVE.getCurve()) && RPhone.isValid())){
            throw new ProtocolException("The point RPhone provided by the phone is invalid");
        }
        R = RPhone.multiply(kDesktop).normalize();
        ECPoint QDesktop = ECKey.CURVE.getG().multiply(privateKey).normalize();
        ZKProofDesktop proof = ZKProofDesktop.generateProof(zDesktop, privateKey.multiply(zDesktop).mod(nEC), r1, r2, R, RPhone, QDesktop,
                ECKey.CURVE.getG(), alphaDesktop, beta, pkpDesktop, desktopBCParameters, zkProofHelper);
        state = States.DecryptEncryptedSignature;
        return new EphemeralPublicValueWithProof(R, proof);
    }

    public ECKey.ECDSASignature decryptEncryptedSignature(EncryptedSignatureWithProof encryptedSignature, byte[] hash){
        if(! state.equals(States.DecryptEncryptedSignature))
            throw new ProtocolException("Operation not allowed in this protocol state.");
        if(encryptedSignature.getSigma().compareTo(BigInteger.ONE) < 0
                || encryptedSignature.getSigma().compareTo(pkpDesktop.getN().pow(2)) >= 0){
            throw new ProtocolException("Sigma is out of bounds.");
        }
        if(encryptedSignature.getAlphaPhone().compareTo(BigInteger.ONE) < 0
                || encryptedSignature.getAlphaPhone().compareTo(pkpPhone.getN().pow(2)) >=0 ){
            throw new ProtocolException("alpha_B is out of bounds.");
        }

        BigInteger hm = new BigInteger(1, hash);
        BigInteger r = R.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger nsquared = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> c1 = zkProofHelper.PowMult(alphaDesktop, hm, nsquared);
        ForkJoinTask<BigInteger> c2 = zkProofHelper.PowMult(beta, r, nsquared);
        encryptedSignature.getProof().verify(c1.join(), c2.join(),
                encryptedSignature.getSigma(), encryptedSignature.getAlphaPhone(), ECKey.CURVE.getG(), otherPublicKey, RPhone,
                pkpDesktop, pkpPhone, phoneBCParameters, zkProofHelper);
        long start = System.currentTimeMillis();
        BigInteger s = pkpDesktop.decrypt(encryptedSignature.getSigma()).mod(nEC);
        System.out.println("decrypt time " + (System.currentTimeMillis() - start) + "ms");
        state = States.Finished;
        return new ECKey.ECDSASignature(r, s);
    }

    protected enum States{
        ComputeSignatureParts, ComputeEphemeralPublicValue, DecryptEncryptedSignature, Finished
    }
}
