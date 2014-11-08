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
 * This class implements the phone's part of the two-party ECDSA signature protocol. The phone takes the side of Bob
 * in the protocol. This class does not return any result. (The resulting ECDSA signature is returned by the
 * {@link de.uni_bonn.bit.DesktopSigner}).
 */
public class PhoneSigner {

    static final BigInteger nEC = ECKey.CURVE.getN();
    PaillierKeyPair pkpDesktop;
    PaillierKeyPair pkpPhone;
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;
    BigInteger privateKey;
    ECPoint otherPublicKey;
    MultiThreadingHelper zkProofHelper;

    private BigInteger alpha;
    private BigInteger beta;
    private BigInteger k2;
    private ECPoint Q2;

    public PhoneSigner(ECKey privateKey, ECKey otherPublicKey, PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                       BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
        this.privateKey = BitcoinECMathHelper.convertPrivKeyToBigInt(privateKey);
        this.otherPublicKey = BitcoinECMathHelper.convertPubKeyToPoint(otherPublicKey);
        this.zkProofHelper = new MultiThreadingHelper();
    }

    public EphemeralValueShare generateEphemeralValueShare(SignatureParts signatureParts){
        alpha = signatureParts.getAlpha();
        beta = signatureParts.getBeta();
        k2 = IntegerFunctions.randomize(nEC);
        Q2 = ECKey.CURVE.getG().multiply(k2).normalize();
        return new EphemeralValueShare(Q2);
    }

    public EncryptedSignatureWithProof computeEncryptedSignature(EphemeralPublicValueWithProof message, byte[] hash){
        ECPoint Q = message.getQ();
        // We first check that Q is associated with the correct curve and then we check that it is on the associated curve.
        if(! (Q.getCurve().equals(ECKey.CURVE.getCurve()) && Q.isValid())){
            throw new ProtocolException("The point Q provided by the desktop is invalid");
        }
        ECPoint QBob = ECKey.CURVE.getG().multiply(privateKey).normalize();
        BigInteger z2 = k2.modInverse(nEC);
        BigInteger r = Q.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger hm = new BigInteger(1, hash);
        BigInteger randomizer = IntegerFunctions.randomize(nEC.pow(5));
        BigInteger r3 = pkpDesktop.generateRandomizer();
//        BigInteger sigma = pkpDesktop.add(
//                pkpDesktop.add(
//                        pkpDesktop.multiplyWithScalar(alpha, z2.multiply(hm)),
//                        pkpDesktop.multiplyWithScalar(beta, z2.multiply(privateKey).mod(nEC).multiply(r))
//                ),
//                pkpDesktop.encrypt(nEC.multiply(randomizer), r3));
        BigInteger nsquaredDesktop = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> sigma = zkProofHelper.PowMult(alpha, z2.multiply(hm), beta, z2.multiply(privateKey).mod(nEC).multiply(r),
                pkpDesktop.getG(), nEC.multiply(randomizer), r3, pkpDesktop.getN(), nsquaredDesktop);

        BigInteger r4 = pkpPhone.generateRandomizer();
        BigInteger nsquaredPhone = pkpPhone.getN().pow(2);
//        BigInteger alphaPrime = pkpPhone.encrypt(z2, r4);
        ForkJoinTask<BigInteger> alphaPrime = zkProofHelper.PowMult(pkpPhone.getG(), z2, r4, pkpPhone.getN(), nsquaredPhone);
        ForkJoinTask<BigInteger> c1 = zkProofHelper.PowMult(alpha, hm, nsquaredDesktop);
        ForkJoinTask<BigInteger> c2 = zkProofHelper.PowMult(beta, r, nsquaredDesktop);

        message.getProof().verify(alpha, beta, ECKey.CURVE.getG(), message.getQ(), otherPublicKey, Q2, pkpDesktop,
                desktopBCParameters, zkProofHelper);
        ZKProofPhone proof = ZKProofPhone.generateProof(z2, privateKey.multiply(z2).mod(nEC), randomizer, r3, r4, message.getQ(), Q2,
                QBob, ECKey.CURVE.getG(), c1.join(), c2.join(),
                sigma.join(), alphaPrime.join(), pkpDesktop, pkpPhone, phoneBCParameters, zkProofHelper);
        return new EncryptedSignatureWithProof(sigma.join(), alphaPrime.join(), proof);
    }
}
