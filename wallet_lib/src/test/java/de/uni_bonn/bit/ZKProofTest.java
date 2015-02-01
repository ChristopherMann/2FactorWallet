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

import de.uni_bonn.bit.wallet_protocol.ZKProofInit;
import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.wallet_protocol.ZKProofDesktop;
import de.uni_bonn.bit.wallet_protocol.ZKProofPhone;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class tests the implementation of the zero-knowledge proofs.
 */
public class ZKProofTest {

    public static final BigInteger nEC = ECKey.CURVE.getN();


    /**
     * This method tests the implementation of the zero-knowledge proof Pi_A in the class
     * {@link de.uni_bonn.bit.wallet_protocol.ZKProofDesktop}
     */
    @Test
    public void ZKProofDesktopTest() {
        ECPoint G = ECKey.CURVE.getG();
        BigInteger dDesktop = IntegerFunctions.randomize(nEC);
        ECPoint QDesktop = G.multiply(dDesktop);
        PaillierKeyPair pkp = PaillierKeyPair.generatePaillierKeyPair();
        BigInteger kDesktop = new BigInteger("2");
        BigInteger zDesktop = kDesktop.modInverse(nEC);
        BigInteger r1 = pkp.generateRandomizer();
        BigInteger alphaDesktop = pkp.encrypt(zDesktop, r1);
        BigInteger r2 = pkp.generateRandomizer();
        BigInteger beta = pkp.encrypt(dDesktop.multiply(zDesktop).mod(nEC), r2);

        BigInteger kPhone = new BigInteger("3");
        ECPoint RPhone = G.multiply(kPhone);

        ECPoint R = RPhone.multiply(kDesktop);

        BCParameters bcParameters =  BCParameters.generateBCParameters();

        MultiThreadingHelper zkProofHelper = new MultiThreadingHelper();
        ZKProofDesktop zkProofDesktop = ZKProofDesktop.generateProof(zDesktop, dDesktop.multiply(zDesktop).mod(nEC), r1, r2, R, RPhone, QDesktop, G, alphaDesktop, beta, pkp, bcParameters, zkProofHelper);
        zkProofDesktop.verify(alphaDesktop, beta, G, R, QDesktop, RPhone, pkp.clearPrivateKey(), bcParameters.clearPrivate(), zkProofHelper);
    }

    /**
     * This method tests the implementation of the zero-knowledge proof Pi_B in the class
     * {@link de.uni_bonn.bit.wallet_protocol.ZKProofPhone}
     */
    @Test
    public void ZKProofPhoneTest(){
        ECPoint G = ECKey.CURVE.getG();
        BigInteger dDesktop = IntegerFunctions.randomize(nEC);
        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();
        BigInteger kDesktop = new BigInteger("2");
        BigInteger zDesktop = kDesktop.modInverse(nEC);
        BigInteger alphaDesktop = pkpDesktop.encrypt(zDesktop);
        BigInteger beta = pkpDesktop.encrypt(dDesktop.multiply(zDesktop).mod(nEC));

        BigInteger dPhone = IntegerFunctions.randomize(nEC);
        ECPoint QPhone = G.multiply(dPhone);
        BigInteger kPhone = new BigInteger("3");
        BigInteger zPhone = kPhone.modInverse(nEC);
        BigInteger c = IntegerFunctions.randomize(nEC.pow(5));
        ECPoint RPhone = G.multiply(kPhone);

        BigInteger r4 = pkpPhone.generateRandomizer();
        BigInteger alphaPhone = pkpPhone.encrypt(zPhone, r4);

        ECPoint R = RPhone.multiply(kDesktop);
        BigInteger r = R.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger hm = new BigInteger("5");
        BigInteger r3 = pkpDesktop.generateRandomizer();
        BigInteger sigma = pkpDesktop.add(
                pkpDesktop.add(
                        pkpDesktop.multiplyWithScalar(alphaDesktop, zPhone.multiply(hm)),
                        pkpDesktop.multiplyWithScalar(beta, zPhone.multiply(dPhone).multiply(r))
                ),
                pkpDesktop.encrypt(nEC.multiply(c), r3));

        BCParameters bcParameters =  BCParameters.generateBCParameters();

        PaillierKeyPair publicPkpDesktop = pkpDesktop.clearPrivateKey();
        MultiThreadingHelper zkProofHelper = new MultiThreadingHelper();
        ZKProofPhone zkProof2 = ZKProofPhone.generateProof(zPhone, dPhone.multiply(zPhone), c, r3, r4, RPhone, QPhone, G,
                publicPkpDesktop.multiplyWithScalar(alphaDesktop, hm), publicPkpDesktop.multiplyWithScalar(beta, r), sigma, alphaPhone,
                publicPkpDesktop, pkpPhone, bcParameters, zkProofHelper);

        zkProof2.verify(pkpDesktop.multiplyWithScalar(alphaDesktop, hm), pkpDesktop.multiplyWithScalar(beta, r), sigma, alphaPhone,
                G, QPhone, RPhone, pkpDesktop, pkpPhone.clearPrivateKey(), bcParameters.clearPrivate(), zkProofHelper);
    }

    @Test
    public void ZKProofInitTest(){
        long time = System.currentTimeMillis();
        BCParameters params = BCParameters.generateBCParameters2();
        System.out.println("time for gen: " + (System.currentTimeMillis() - time));
        ZKProofInit proof = ZKProofInit.generate(params, "init proof test");

        BCParameters publicParams = params.clearPrivate();
        proof.verify(publicParams, "init proof test");
    }
}
