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
import java.util.concurrent.ForkJoinTask;

/**
 * This class represents the zero knowledge proof Pi_B. It is transferred from the desktop to the phone. It contains
 * the logic to create and verify instances of the proof. It makes use of a helper class which uses Java's ForkJoinTask
 * to parallelize the expensive BitInteger computations.
 */
public class ZKProofPhone {

    private static final BigInteger nEC = ECKey.CURVE.getN();

    @Stringable
    private BigInteger s1, s2, s3;
    @Stringable
    private BigInteger t1,t2,t3,t4,t5,t6;
    @Stringable
    private BigInteger z1,z2,z3;
    @Stringable
    private BigInteger e;
    private byte[] Y;

    public static ZKProofPhone generateProof(BigInteger x1, BigInteger x2, BigInteger x3, BigInteger r3, BigInteger r4,
                                         ECPoint RPhone, ECPoint QPhone, ECPoint G,
                                         BigInteger c1, BigInteger c2, BigInteger c3, BigInteger c4,
                                         PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone, BCParameters bcParameters,
                                         MultiThreadingHelper zkProofHelper){
        final BigInteger NsquaredDesktop = pkpDesktop.getN().pow(2);
        final BigInteger NsquaredPhone = pkpPhone.getN().pow(2);

        BigInteger alpha = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger beta = IntegerFunctions.randomize(pkpPhone.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger gamma = IntegerFunctions.randomize(nEC.pow(3).multiply(bcParameters.getN()));
        BigInteger rho1 = IntegerFunctions.randomize(nEC.multiply(bcParameters.getN()));

        BigInteger delta = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger mu = IntegerFunctions.randomize(pkpDesktop.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger nu = IntegerFunctions.randomize(nEC.pow(3).multiply(bcParameters.getN()));
        BigInteger rho2 = IntegerFunctions.randomize(nEC.multiply(bcParameters.getN()));
        BigInteger rho3 = IntegerFunctions.randomize(nEC);
        BigInteger rho4 = IntegerFunctions.randomize(nEC.pow(5).multiply(bcParameters.getN()));
        BigInteger epsilon = IntegerFunctions.randomize(nEC);
        BigInteger sigma = IntegerFunctions.randomize(nEC.pow(7));
        BigInteger tau = IntegerFunctions.randomize(nEC.pow(7).multiply(bcParameters.getN()));

        //ECPoint multiplications

        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(alpha, RPhone);
        ForkJoinTask<ECPoint> Y = zkProofHelper.pointMultAdd(x2.add(rho3), G);
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(delta.add(epsilon), G);
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(alpha, QPhone, epsilon, G);

        ForkJoinTask<BigInteger> z1 = zkProofHelper.PowMult(bcParameters.getH(), x1, bcParameters.getG(), rho1, bcParameters.getN());
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkpPhone.getG(), alpha, beta, pkpPhone.getN(), NsquaredPhone);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(bcParameters.getH(), alpha, bcParameters.getG(), gamma, bcParameters.getN());

        ForkJoinTask<BigInteger> z2 = zkProofHelper.PowMult(bcParameters.getH(), x2, bcParameters.getG(), rho2, bcParameters.getN());
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(c1, alpha, c2, delta, pkpDesktop.getG(), nEC.multiply(sigma), mu, pkpDesktop.getN(), NsquaredDesktop);

        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(bcParameters.getH(), delta, bcParameters.getG(), nu, bcParameters.getN());
        ForkJoinTask<BigInteger> z3 = zkProofHelper.PowMult(bcParameters.getH(), x3, bcParameters.getG(), rho4, bcParameters.getN());
        ForkJoinTask<BigInteger> v5 = zkProofHelper.PowMult(bcParameters.getH(), sigma, bcParameters.getG(), tau, bcParameters.getN());


        BigInteger e = MultiThreadingHelper.hash("PiPrime", RPhone, G, G, QPhone, c4, c3, z1.join(), U1.join(), u2.join(), u3.join(), z2.join(), z3.join(), Y.join(), V1.join(), V2.join(), v3.join(), v4.join(), v5.join());

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = r4.modPow(e, NsquaredPhone).multiply(beta).mod(NsquaredPhone);
        BigInteger s3 = e.multiply(rho1).add(gamma);

        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(nEC);
        BigInteger t3 = r3.modPow(e, NsquaredDesktop).multiply(mu).mod(NsquaredDesktop);
        BigInteger t4 = e.multiply(rho2).add(nu);
        BigInteger t5 = e.multiply(x3).add(sigma);
        BigInteger t6 = e.multiply(rho4).add(tau);

        ZKProofPhone result = new ZKProofPhone();
        result.z1 = z1.join();
        result.z2 = z2.join();
        result.z3 = z3.join();
        result.Y = Y.join().getEncoded();
        result.e = e;
        result.s1 = s1;
        result.s2 = s2;
        result.s3 = s3;
        result.t1 = t1;
        result.t2 = t2;
        result.t3 = t3;
        result.t4 = t4;
        result.t5 = t5;
        result.t6 = t6;
        return result;
    }

    public void verify(BigInteger c1, BigInteger c2, BigInteger c3, BigInteger c4, ECPoint G,
                       ECPoint QPhone, ECPoint RPhone, PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone, BCParameters bcParameters,
                       MultiThreadingHelper zkProofHelper){
        final BigInteger NsquaredDesktop = pkpDesktop.getN().pow(2);
        final BigInteger NsquaredPhone = pkpPhone.getN().pow(2);

        ECPoint Y = ECKey.CURVE.getCurve().decodePoint(this.Y).normalize();
        //check that 0 <= t1 < nEC^3
        if(!(s1.compareTo(BigInteger.ZERO) >= 0 && s1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("s1 out of bounds");
        //check that 0 <= t1 < nEC^3
        if(!(t1.compareTo(BigInteger.ZERO) >= 0 && t1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("t1 out of bounds");
        //check that 0 <= t5 < nEC^7
        if(!(t5.compareTo(BigInteger.ZERO) >= 0 && t5.compareTo(nEC.pow(7)) <0))
            throw new RuntimeException("t5 out of bounds");

        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(s1, RPhone, e.negate(), G);

        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkpPhone.getG(), s1, s2, pkpPhone.getN(), c4, e.negate(), NsquaredPhone);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(bcParameters.getH(), s1, bcParameters.getG(), s3, z1, e.negate(), bcParameters.getN());

        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(t1.add(t2), G, e.negate(), Y);
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(s1, QPhone, t2, G, e.negate(), Y);
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(c1, s1, c2, t1, pkpDesktop.getG(), nEC.multiply(t5), t3, pkpDesktop.getN(), c3, e.negate(), NsquaredDesktop);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(bcParameters.getH(), t1, bcParameters.getG(), t4, z2, e.negate(), bcParameters.getN());
        ForkJoinTask<BigInteger> v5 = zkProofHelper.PowMult(bcParameters.getH(), t5, bcParameters.getG(), t6, z3, e.negate(), bcParameters.getN());

        BigInteger eToCheck = MultiThreadingHelper.hash("PiPrime", RPhone, G, G, QPhone, c4, c3, z1, U1.join(), u2.join(), u3.join(), z2, z3, Y, V1.join(), V2.join(), v3.join(), v4.join(), v5.join());
        if(! e.equals(eToCheck))
            throw new ProtocolException("Verification of hash value e failed");
    }
}
