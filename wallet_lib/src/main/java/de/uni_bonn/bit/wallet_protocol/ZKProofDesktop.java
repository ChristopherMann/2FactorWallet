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
                                         ECPoint QCommon, ECPoint Q2, ECPoint QAlice, ECPoint G,
                                         BigInteger c1, BigInteger c2, PaillierKeyPair pkp, BCParameters bcParameters,
                                         MultiThreadingHelper zkProofHelper){
        final BigInteger Nsquared = pkp.getN().pow(2);
        final BigInteger h1 = bcParameters.getH1(); final BigInteger h2 = bcParameters.getH2();
        final BigInteger Ntilla = bcParameters.getNtilla();

        BigInteger alpha = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger beta = IntegerFunctions.randomize(pkp.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger gamma = IntegerFunctions.randomize(nEC.pow(3).multiply(Ntilla));
        BigInteger rho1 = IntegerFunctions.randomize(nEC.multiply(Ntilla));

        BigInteger delta = IntegerFunctions.randomize(nEC.pow(3));
        BigInteger mu = IntegerFunctions.randomize(pkp.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger nu = IntegerFunctions.randomize(nEC.pow(3).multiply(Ntilla));
        BigInteger rho2 = IntegerFunctions.randomize(nEC.multiply(Ntilla));
        BigInteger rho3 = IntegerFunctions.randomize(nEC);
        BigInteger epsilon = IntegerFunctions.randomize(nEC);

//        BigInteger z1 = h1.modPow(x1, Ntilla).multiply(h2.modPow(rho1, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> z1 = zkProofHelper.PowMult(h1, x1, h2, rho1, Ntilla);
//        BigInteger u2 = pkp.getG().modPow(alpha, Nsquared).multiply(
//                beta.modPow(pkp.getN(), Nsquared))
//                .mod(Nsquared);
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkp.getG(), alpha, beta, pkp.getN(), Nsquared);
//        BigInteger u3 = h1.modPow(alpha, Ntilla).multiply(h2.modPow(gamma, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(h1, alpha, h2, gamma, Ntilla);
//
//        BigInteger z2 = h1.modPow(x2, Ntilla).multiply(h2.modPow(rho2, Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> z2 = zkProofHelper.PowMult(h1, x2, h2, rho2, Ntilla);
//
//        BigInteger v3 = pkp.getG().modPow(delta, Nsquared).multiply(mu.modPow(pkp.getN(), Nsquared)).mod(Nsquared);
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(pkp.getG(), delta, mu, pkp.getN(), Nsquared);
//        BigInteger v4 = h1.modPow(delta, Ntilla).multiply(h2.modPow(nu,Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(h1, delta, h2, nu, Ntilla);

        //Computing point multiplications
        /*
        U1 = QCommon.multiply(alpha);
        Y = G.multiply(x2.add(rho3));
        V1 = G.multiply(delta.add(epsilon))
        T1 = QAlice.multiply(alpha)
        T2 = G.multiply(epsilon)
        V2 = QAlice.multiply(alpha.mod(nEC)).add(G.multiply(epsilon.mod(nEC))).normalize();
         */
//        ECPoint U1 = QCommon.multiply(alpha.mod(nEC)).normalize();
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(alpha, QCommon);
//        ECPoint Y = G.multiply(x2.add(rho3)).normalize();
        ForkJoinTask<ECPoint> Y = zkProofHelper.pointMultAdd(x2.add(rho3), G);
//        ECPoint V1 = G.multiply(delta.add(epsilon).mod(nEC)).normalize();
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(delta.add(epsilon), G);
//        ECPoint V2 = QAlice.multiply(alpha.mod(nEC)).add(G.multiply(epsilon.mod(nEC))).normalize();
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(alpha, QAlice, epsilon, G);

        BigInteger e = MultiThreadingHelper.hash("Pi", QCommon, Q2, G, QAlice, c1, c2, z1.join(), U1.join(), u2.join(), u3.join(), z2.join(), Y.join(), V1.join(), V2.join(), v3.join(), v4.join());

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = r1.modPow(e, Nsquared).multiply(beta).mod(Nsquared);
        BigInteger s3 = e.multiply(rho1).add(gamma);

        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(nEC);
        BigInteger t3 = r2.modPow(e, Nsquared).multiply(mu).mod(Nsquared);
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

    public void verify(BigInteger c1, BigInteger c2, ECPoint G,  ECPoint QCommon, ECPoint QAlice, ECPoint Q2,
                       PaillierKeyPair pkp, BCParameters bcParameters, MultiThreadingHelper zkProofHelper){
        System.out.println("Pi Trace 1: " + 0);
        final BigInteger Nsquared = pkp.getN().pow(2);
        final BigInteger h1 = bcParameters.getH1(); final BigInteger h2 = bcParameters.getH2();
        final BigInteger Ntilla = bcParameters.getNtilla();
        ECPoint Y = ECKey.CURVE.getCurve().decodePoint(this.Y).normalize();
        //check that 0 <= t1 < nEC^3
        if(!(s1.compareTo(BigInteger.ZERO) >= 0 && s1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("s1 out of bounds");
        //check that 0 <= t1 < nEC^3
        if(!(t1.compareTo(BigInteger.ZERO) >= 0 && t1.compareTo(nEC.pow(3)) <0))
            throw new RuntimeException("s1 out of bounds");

//        BigInteger u2 = pkp.getG().modPow(s1, Nsquared)
//                .multiply(s2.modPow(pkp.getN(), Nsquared)).mod(Nsquared)
//                .multiply(c1.modPow(e.negate(), Nsquared)).mod(Nsquared);
        ForkJoinTask<BigInteger> u2 = zkProofHelper.PowMult(pkp.getG(), s1, s2, pkp.getN(), c1, e.negate(), Nsquared);
//        BigInteger u3 = h1.modPow(s1, Ntilla)
//                .multiply(h2.modPow(s3, Ntilla)).mod(Ntilla)
//                .multiply(z1.modPow(e.negate(), Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> u3 = zkProofHelper.PowMult(h1, s1, h2, s3, z1, e.negate(), Ntilla);

//        BigInteger v3 = pkp.getG().modPow(t1, Nsquared)
//                .multiply(t3.modPow(pkp.getN(), Nsquared)).mod(Nsquared)
//                .multiply(c2.modPow(e.negate(), Nsquared)).mod(Nsquared);
        ForkJoinTask<BigInteger> v3 = zkProofHelper.PowMult(pkp.getG(), t1, t3, pkp.getN(), c2, e.negate(), Nsquared);
//        BigInteger v4 = h1.modPow(t1, Ntilla)
//                .multiply(h2.modPow(t4, Ntilla)).mod(Ntilla)
//                .multiply(z2.modPow(e.negate(), Ntilla)).mod(Ntilla);
        ForkJoinTask<BigInteger> v4 = zkProofHelper.PowMult(h1, t1, h2, t4, z2, e.negate(), Ntilla);


        //ECPoint multiplication
        //ECPoint U1P = QCommon.multiply(s1).add(Q2.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> U1 = zkProofHelper.pointMultAdd(s1, QCommon, e.negate(), Q2);
        //ECPoint V1P = G.multiply(t1.add(t2).mod(nEC)).add(Y.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> V1 = zkProofHelper.pointMultAdd(t1.add(t2), G, e.negate(), Y);
        //ECPoint V2P = QAlice.multiply(s1.mod(nEC)).add(G.multiply(t2.mod(nEC))).add(Y.multiply(e.negate())).normalize();
        ForkJoinTask<ECPoint> V2 = zkProofHelper.pointMultAdd(s1, QAlice, t2, G, e.negate(), Y);


        BigInteger eToCheck = MultiThreadingHelper.hash("Pi", QCommon, Q2, G, QAlice, c1, c2, z1, U1.join(), u2.join(), u3.join(), z2, Y, V1.join(), V2.join(), v3.join(), v4.join());
        if(! e.equals(eToCheck))
            throw new ProtocolException("Verification of hash value e failed");
    }

    public class PointMultiplication extends RecursiveTask<ECPoint> {

        final BigInteger scalar;
        final ECPoint point;

        public PointMultiplication(BigInteger scalar, ECPoint point) {
            this.scalar = scalar;
            this.point = point;
        }

        @Override
        protected ECPoint compute() {
            return point.multiply(scalar);
        }
    }

}
