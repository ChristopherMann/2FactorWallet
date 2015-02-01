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
package de.uni_bonn.bit.wallet_protocol;

import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.BCParameters;
import de.uni_bonn.bit.MultiThreadingHelper;
import de.uni_bonn.bit.PaillierKeyPair;
import de.uni_bonn.bit.ProtocolException;
import org.apache.avro.reflect.Stringable;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;
import java.util.concurrent.*;

/**
 * This class represents the zero knowledge proof Pi_A. It is transferred from the desktop to the phone. It contains
 * the logic to create and verify instances of the proof.  It makes use of a helper class which uses Java's ForkJoinTask
 * to parallelize the expensive BitInteger computations.
 */
public class ZKProofDesktop {

    private static final BigInteger nEC = ECKey.CURVE.getN();

    @Stringable
    private BigInteger s1, s2, s3;
    @Stringable
    private BigInteger t1,t2,t3,t4;
    @Stringable
    private BigInteger z1,z2;
    @Stringable
    private BigInteger e;
    private byte[] Y;

    public static ZKProofDesktop generateProof(BigInteger x1, BigInteger x2, BigInteger r1, BigInteger r2,
                                         ECPoint R, ECPoint RPhone, ECPoint QDesktop, ECPoint G,
                                         BigInteger c1, BigInteger c2, PaillierKeyPair pkpDesktop, BCParameters bcParameters,
                                         MultiThreadingHelper zkProofHelper){
        final BigInteger NsquaredDesktop = pkpDesktop.getN().pow(2);

        BigInteger alpha = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger beta = IntegerFunctions.randomize(pkpDesktop.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger gamma = IntegerFunctions.randomize(nEC.pow(3).multiply(bcParameters.getN()));
        BigInteger rho1 = IntegerFunctions.randomize(nEC.multiply(bcParameters.getN()));

        BigInteger delta = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger mu = IntegerFunctions.randomize(pkpDesktop.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger nu = IntegerFunctions.randomize(nEC.pow(3).multiply(bcParameters.getN()));
        BigInteger rho2 = IntegerFunctions.randomize(nEC.multiply(bcParameters.getN()));
        BigInteger rho3 = IntegerFunctions.randomize(nEC);
        BigInteger epsilon = IntegerFunctions.randomize(nEC);

        ForkJoinTask<BigInteger> z1 = zkProofHelper.PowMult(bcParameters.getH(), x1, bcParameters.getG(), rho1, bcParameters.getN());
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkpDesktop.getG(), alpha, beta, pkpDesktop.getN(), NsquaredDesktop);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(bcParameters.getH(), alpha, bcParameters.getG(), gamma, bcParameters.getN());
        ForkJoinTask<BigInteger> z2 = zkProofHelper.PowMult(bcParameters.getH(), x2, bcParameters.getG(), rho2, bcParameters.getN());
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(pkpDesktop.getG(), delta, mu, pkpDesktop.getN(), NsquaredDesktop);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(bcParameters.getH(), delta, bcParameters.getG(), nu, bcParameters.getN());

        //ECPoint multiplication
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(alpha, R);
        ForkJoinTask<ECPoint> Y = zkProofHelper.pointMultAdd(x2.add(rho3), G);
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(delta.add(epsilon), G);
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(alpha, QDesktop, epsilon, G);

        BigInteger e = MultiThreadingHelper.hash("Pi", R, RPhone, G, QDesktop, c1, c2, z1.join(), U1.join(), u2.join(), u3.join(), z2.join(), Y.join(), V1.join(), V2.join(), v3.join(), v4.join());

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = r1.modPow(e, NsquaredDesktop).multiply(beta).mod(NsquaredDesktop);
        BigInteger s3 = e.multiply(rho1).add(gamma);

        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(nEC);
        BigInteger t3 = r2.modPow(e, NsquaredDesktop).multiply(mu).mod(NsquaredDesktop);
        BigInteger t4 = e.multiply(rho2).add(nu);

        ZKProofDesktop result = new ZKProofDesktop();
        result.z1 = z1.join();
        result.z2 = z2.join();
        result.Y = Y.join().getEncoded();
        result.e = e;
        result.s1 = s1;
        result.s2 = s2;
        result.s3 = s3;
        result.t1 = t1;
        result.t2 = t2;
        result.t3 = t3;
        result.t4 = t4;
        return result;
    }

    public void verify(BigInteger c1, BigInteger c2, ECPoint G, ECPoint R, ECPoint QDesktop, ECPoint RPhone,
                       PaillierKeyPair pkpDesktop, BCParameters bcParameters, MultiThreadingHelper zkProofHelper){
        System.out.println("Pi Trace 1: " + 0);
        final BigInteger NsquaredDesktop = pkpDesktop.getN().pow(2);
        ECPoint Y = ECKey.CURVE.getCurve().decodePoint(this.Y).normalize();
        //check that 0 <= t1 < nEC^3
        if(!(s1.compareTo(BigInteger.ZERO) >= 0 && s1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("s1 out of bounds");
        //check that 0 <= t1 < nEC^3
        if(!(t1.compareTo(BigInteger.ZERO) >= 0 && t1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("s1 out of bounds");

        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkpDesktop.getG(), s1, s2, pkpDesktop.getN(), c1, e.negate(), NsquaredDesktop);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(bcParameters.getH(), s1, bcParameters.getG(), s3, z1, e.negate(), bcParameters.getN());

        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(pkpDesktop.getG(), t1, t3, pkpDesktop.getN(), c2, e.negate(), NsquaredDesktop);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(bcParameters.getH(), t1, bcParameters.getG(), t4, z2, e.negate(), bcParameters.getN());


        //ECPoint multiplication
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(s1, R, e.negate(), RPhone);
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(t1.add(t2), G, e.negate(), Y);
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(s1, QDesktop, t2, G, e.negate(), Y);


        BigInteger eToCheck = MultiThreadingHelper.hash("Pi", R, RPhone, G, QDesktop, c1, c2, z1, U1.join(), u2.join(), u3.join(), z2, Y, V1.join(), V2.join(), v3.join(), v4.join());
        if(! e.equals(eToCheck))
            throw new ProtocolException("Verification of hash value e failed");
    }
}
