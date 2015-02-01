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
    MultiThreadingHelper multiThreadingHelper;

    private BigInteger alphaDesktop;
    private BigInteger beta;
    private BigInteger kPhone;
    private ECPoint RPhone;

    public PhoneSigner(ECKey privateKey, ECKey otherPublicKey, PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                       BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
        this.privateKey = BitcoinECMathHelper.convertPrivKeyToBigInt(privateKey);
        this.otherPublicKey = BitcoinECMathHelper.convertPubKeyToPoint(otherPublicKey);
        this.multiThreadingHelper = new MultiThreadingHelper();
    }

    public EphemeralValueShare generateEphemeralValueShare(SignatureParts signatureParts){
        alphaDesktop = signatureParts.getAlphaDesktop();
        beta = signatureParts.getBeta();
        kPhone = IntegerFunctions.randomize(nEC);
        RPhone = ECKey.CURVE.getG().multiply(kPhone).normalize();
        return new EphemeralValueShare(RPhone);
    }

    public EncryptedSignatureWithProof computeEncryptedSignature(EphemeralPublicValueWithProof message, byte[] hash){
        ECPoint R = message.getR();
        // We first check that R is associated with the correct curve and then we check that it is on the associated curve.
        if(! (R.getCurve().equals(ECKey.CURVE.getCurve()) && R.isValid())){
            throw new ProtocolException("The point R provided by the desktop is invalid");
        }
        ECPoint QPhone = ECKey.CURVE.getG().multiply(privateKey).normalize();
        BigInteger zPhone = kPhone.modInverse(nEC);
        BigInteger r = R.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger hm = new BigInteger(1, hash);
        BigInteger randomizer = IntegerFunctions.randomize(nEC.pow(5));
        BigInteger r3 = pkpDesktop.generateRandomizer();
        BigInteger nsquaredDesktop = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> sigma = multiThreadingHelper.PowMult(alphaDesktop, zPhone.multiply(hm), beta, zPhone.multiply(privateKey).mod(nEC).multiply(r),
                pkpDesktop.getG(), nEC.multiply(randomizer), r3, pkpDesktop.getN(), nsquaredDesktop);

        BigInteger r4 = pkpPhone.generateRandomizer();
        BigInteger nsquaredPhone = pkpPhone.getN().pow(2);
        ForkJoinTask<BigInteger> alphaPhone = multiThreadingHelper.PowMult(pkpPhone.getG(), zPhone, r4, pkpPhone.getN(), nsquaredPhone);
        ForkJoinTask<BigInteger> c1 = multiThreadingHelper.PowMult(alphaDesktop, hm, nsquaredDesktop);
        ForkJoinTask<BigInteger> c2 = multiThreadingHelper.PowMult(beta, r, nsquaredDesktop);

        message.getProof().verify(alphaDesktop, beta, ECKey.CURVE.getG(), message.getR(), otherPublicKey, RPhone, pkpDesktop,
                desktopBCParameters, multiThreadingHelper);
        ZKProofPhone proof = ZKProofPhone.generateProof(zPhone, privateKey.multiply(zPhone).mod(nEC), randomizer, r3, r4, RPhone,
                QPhone, ECKey.CURVE.getG(), c1.join(), c2.join(),
                sigma.join(), alphaPhone.join(), pkpDesktop, pkpPhone, phoneBCParameters, multiThreadingHelper);
        return new EncryptedSignatureWithProof(sigma.join(), alphaPhone.join(), proof);
    }
}
