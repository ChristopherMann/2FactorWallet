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
                                         ECPoint QCommon, ECPoint Q2, ECPoint QBob, ECPoint G,
                                         BigInteger c1, BigInteger c2, BigInteger c3, BigInteger c4,
                                         PaillierKeyPair pkp, PaillierKeyPair pkp2, BCParameters bcParameters,
                                         MultiThreadingHelper zkProofHelper){
        final BigInteger Nsquared = pkp.getN().pow(2);
        final BigInteger Nsquared2 = pkp2.getN().pow(2);
        final BigInteger h1 = bcParameters.getH1(); final BigInteger h2 = bcParameters.getH2();
        final BigInteger Ntilla = bcParameters.getNtilla();

        BigInteger alpha = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger beta = IntegerFunctions.randomize(pkp2.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger gamma = IntegerFunctions.randomize(nEC.pow(3).multiply(Ntilla));
        BigInteger rho1 = IntegerFunctions.randomize(nEC.multiply(Ntilla));

        BigInteger delta = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger mu = IntegerFunctions.randomize(pkp.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger nu = IntegerFunctions.randomize(nEC.pow(3).multiply(Ntilla));
        BigInteger rho2 = IntegerFunctions.randomize(nEC.multiply(Ntilla));
        BigInteger rho3 = IntegerFunctions.randomize(nEC);
        BigInteger rho4 = IntegerFunctions.randomize(nEC.pow(5).multiply(Ntilla));
        BigInteger epsilon = IntegerFunctions.randomize(nEC);
        BigInteger sigma = IntegerFunctions.randomize(nEC.pow(7));
        BigInteger tau = IntegerFunctions.randomize(nEC.pow(7).multiply(Ntilla));

        //ECPoint multiplications

        //ECPoint U1 = Q2.multiply(alpha.mod(nEC)).normalize();
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(alpha, Q2);
        //ECPoint Y = G.multiply(x2.add(rho3).mod(nEC)).normalize();
        ForkJoinTask<ECPoint> Y = zkProofHelper.pointMultAdd(x2.add(rho3), G);
        //ECPoint V1 = G.multiply(delta.add(epsilon).mod(nEC)).normalize();
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(delta.add(epsilon), G);
        //ECPoint V2 = QBob.multiply(alpha.mod(nEC)).add(G.multiply(epsilon.mod(nEC))).normalize();
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(alpha, QBob, epsilon, G);

//        BigInteger z1 = h1.modPow(x1, Ntilla).multiply(h2.modPow(rho1, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> z1 = zkProofHelper.PowMult(h1, x1, h2, rho1, Ntilla);
//        BigInteger u2 = pkp2.getG().modPow(alpha, Nsquared2).multiply(
//                beta.modPow(pkp2.getN(), Nsquared2))
//                .mod(Nsquared2);
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkp2.getG(), alpha, beta, pkp2.getN(), Nsquared2);
//        BigInteger u3 = h1.modPow(alpha, Ntilla).multiply(h2.modPow(gamma, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(h1, alpha, h2, gamma, Ntilla);
//
//        BigInteger z2 = h1.modPow(x2, Ntilla).multiply(h2.modPow(rho2, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> z2 = zkProofHelper.PowMult(h1, x2, h2, rho2, Ntilla);
//        BigInteger v3 = c1.modPow(alpha, Nsquared)
//                .multiply(c2.modPow(delta, Nsquared)).mod(Nsquared)
//                .multiply(pkp.getG().modPow(nEC.multiply(sigma), Nsquared)).mod(Nsquared)
//                .multiply(mu.modPow(pkp.getN(), Nsquared)).mod(Nsquared);
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(c1, alpha, c2, delta, pkp.getG(), nEC.multiply(sigma), mu, pkp.getN(), Nsquared);
//
//        BigInteger v4 = h1.modPow(delta, Ntilla).multiply(h2.modPow(nu,Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(h1, delta, h2, nu, Ntilla);
//        BigInteger z3 = h1.modPow(x3, Ntilla).multiply(h2.modPow(rho4, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> z3 = zkProofHelper.PowMult(h1, x3, h2, rho4, Ntilla);
//        BigInteger v5 = h1.modPow(sigma, Ntilla).multiply(h2.modPow(tau, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> v5 = zkProofHelper.PowMult(h1, sigma, h2, tau, Ntilla);


        BigInteger e = MultiThreadingHelper.hash("PiPrime", Q2, G, G, QBob, c4, c3, z1.join(), U1.join(), u2.join(), u3.join(), z2.join(), z3.join(), Y.join(), V1.join(), V2.join(), v3.join(), v4.join(), v5.join());

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = r4.modPow(e, Nsquared2).multiply(beta).mod(Nsquared2);
        BigInteger s3 = e.multiply(rho1).add(gamma);

        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(nEC);
        BigInteger t3 = r3.modPow(e, Nsquared).multiply(mu).mod(Nsquared);
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

    public void verify(BigInteger c1, BigInteger c2, BigInteger c3, BigInteger c4, ECPoint G,  ECPoint QCommon,
                       ECPoint QBob, ECPoint Q2, PaillierKeyPair pkp, PaillierKeyPair pkp2, BCParameters bcParameters,
                       MultiThreadingHelper zkProofHelper){
        final BigInteger Nsquared = pkp.getN().pow(2);
        final BigInteger Nsquared2 = pkp2.getN().pow(2);
        final BigInteger h1 = bcParameters.getH1(); final BigInteger h2 = bcParameters.getH2();
        final BigInteger Ntilla = bcParameters.getNtilla();

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

//        ECPoint U1 = Q2.multiply(s1.mod(nEC)).add(G.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(s1, Q2, e.negate(), G);

//        BigInteger u2 = pkp2.getG().modPow(s1, Nsquared2)
//                .multiply(s2.modPow(pkp2.getN(), Nsquared2))
//                .multiply(c4.modPow(e.negate(), Nsquared2))
//                .mod(Nsquared2);
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkp2.getG(), s1, s2, pkp2.getN(), c4, e.negate(), Nsquared2);
//        BigInteger u3 = h1.modPow(s1,Ntilla)
//                .multiply(h2.modPow(s3, Ntilla))
//                .multiply(z1.modPow(e.negate(), Ntilla))
//                .mod(Ntilla);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(h1, s1, h2, s3, z1, e.negate(), Ntilla);

//        ECPoint V1 = G.multiply(t1.add(t2).mod(nEC)).add(Y.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(t1.add(t2), G, e.negate(), Y);
//        ECPoint V2 = QBob.multiply(s1.mod(nEC)).add(G.multiply(t2.mod(nEC))).add(Y.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(s1, QBob, t2, G, e.negate(), Y);
//        BigInteger v3 = c1.modPow(s1, Nsquared)
//                .multiply(c2.modPow(t1, Nsquared))
//                .multiply(pkp.getG().modPow(nEC.multiply(t5), Nsquared))
//                .multiply(t3.modPow(pkp.getN(), Nsquared))
//                .multiply(c3.modPow(e.negate(), Nsquared))
//                .mod(Nsquared);
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(c1, s1, c2, t1, pkp.getG(), nEC.multiply(t5), t3, pkp.getN(), c3, e.negate(), Nsquared);
//        BigInteger v4 = h1.modPow(t1, Ntilla)
//                .multiply(h2.modPow(t4, Ntilla))
//                .multiply(z2.modPow(e.negate(), Ntilla))
//                .mod(Ntilla);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(h1, t1, h2, t4, z2, e.negate(), Ntilla);
//        BigInteger v5 = h1.modPow(t5, Ntilla)
//                .multiply(h2.modPow(t6, Ntilla))
//                .multiply(z3.modPow(e.negate(), Ntilla))
//                .mod(Ntilla);
        ForkJoinTask<BigInteger> v5 = zkProofHelper.PowMult(h1, t5, h2, t6, z3, e.negate(), Ntilla);

        BigInteger eToCheck = MultiThreadingHelper.hash("PiPrime", Q2, G, G, QBob, c4, c3, z1, U1.join(), u2.join(), u3.join(), z2, z3, Y, V1.join(), V2.join(), v3.join(), v4.join(), v5.join());
        if(! e.equals(eToCheck))
            throw new ProtocolException("Verification of hash value e failed");
    }
}
