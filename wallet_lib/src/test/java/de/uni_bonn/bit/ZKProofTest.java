package de.uni_bonn.bit;

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
    public void ZKProof1Test() {
        ECPoint G = ECKey.CURVE.getG();
        BigInteger dAlice = IntegerFunctions.randomize(nEC);
        ECPoint QAlice = G.multiply(dAlice);
        PaillierKeyPair pkp = PaillierKeyPair.generatePaillierKeyPair();
        BigInteger k1 = new BigInteger("2");
        BigInteger z1 = k1.modInverse(nEC);
        BigInteger r1 = pkp.generateRandomizer();
        BigInteger alpha = pkp.encrypt(z1, r1);
        BigInteger r2 = pkp.generateRandomizer();
        BigInteger beta = pkp.encrypt(dAlice.multiply(z1).mod(nEC), r2);
        ECPoint Q1 = ECKey.CURVE.getG().multiply(k1);

        BigInteger k2 = new BigInteger("3");
        ECPoint Q2 = G.multiply(k2);

        ECPoint QCommon = Q2.multiply(k1);

        BCParameters bcParameters =  BCParameters.generateBCParameters(nEC.bitLength()*5);

        MultiThreadingHelper zkProofHelper = new MultiThreadingHelper();
        ZKProofDesktop zkProof1 = ZKProofDesktop.generateProof(z1, dAlice.multiply(z1).mod(nEC), r1, r2, QCommon, Q2, QAlice, G, alpha, beta, pkp, bcParameters, zkProofHelper);
        zkProof1.verify(alpha, beta, G, QCommon, QAlice, Q2, pkp, bcParameters, zkProofHelper);
    }

    /**
     * This method tests the implementation of the zero-knowledge proof Pi_B in the class
     * {@link de.uni_bonn.bit.wallet_protocol.ZKProofPhone}
     */
    @Test
    public void ZKProof2Test(){
        ECPoint G = ECKey.CURVE.getG();
        BigInteger dAlice = IntegerFunctions.randomize(nEC);
        ECPoint QAlice = G.multiply(dAlice);
        PaillierKeyPair pkp = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkp2 = PaillierKeyPair.generatePaillierKeyPair();
        BigInteger k1 = new BigInteger("2");
        BigInteger z1 = k1.modInverse(nEC);
        BigInteger alpha = pkp.encrypt(z1);
        BigInteger beta = pkp.encrypt(dAlice.multiply(z1).mod(nEC));
        ECPoint Q1 = ECKey.CURVE.getG().multiply(k1);

        BigInteger dBob = IntegerFunctions.randomize(nEC);
        ECPoint QBob = G.multiply(dBob);
        BigInteger k2 = new BigInteger("3");
        BigInteger z2 = k2.modInverse(nEC);
        BigInteger c = IntegerFunctions.randomize(nEC.pow(5));
        ECPoint Q2 = G.multiply(k2);

        BigInteger r4 = pkp2.generateRandomizer();
        BigInteger alphaPrime = pkp2.encrypt(z2, r4);

        ECPoint QCommon = Q2.multiply(k1);
        BigInteger rPrime = QCommon.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger hm = new BigInteger("5");
        BigInteger r3 = pkp.generateRandomizer();
        BigInteger sigma = pkp.add(
                pkp.add(
                        pkp.multiplyWithScalar(alpha, z2.multiply(hm)),
                        pkp.multiplyWithScalar(beta, z2.multiply(dBob).multiply(rPrime))
                ),
                pkp.encrypt(nEC.multiply(c), r3));

        BCParameters bcParameters =  BCParameters.generateBCParameters(nEC.bitLength()*5);

        MultiThreadingHelper zkProofHelper = new MultiThreadingHelper();
        ZKProofPhone zkProof2 = ZKProofPhone.generateProof(z2, dBob.multiply(z2), c, r3, r4, QCommon, Q2, QBob, G,
                pkp.multiplyWithScalar(alpha, hm), pkp.multiplyWithScalar(beta, rPrime), sigma, alphaPrime,
                pkp, pkp2, bcParameters, zkProofHelper);

        zkProof2.verify(pkp.multiplyWithScalar(alpha, hm), pkp.multiplyWithScalar(beta, rPrime), sigma, alphaPrime,
                G, QCommon, QBob, Q2, pkp, pkp2, bcParameters, zkProofHelper);
    }

    @Ignore
    @Test
    public void benchmarkSafePrimeGen(){
        final BigInteger ONE = BigInteger.ONE;
        final BigInteger TWO = new BigInteger("2");
        SecureRandom sr = new SecureRandom();
        long iterations = 10;
        long cumulatedRuntime = 0;
        for(int i = 0; i < iterations; i ++){
            long starTime = System.currentTimeMillis();
            BigInteger safePrime = BCParameters.generateSafePrime2(512, sr);
            long endTime = System.currentTimeMillis();
            Assert.assertTrue(safePrime.isProbablePrime(100) && safePrime.subtract(ONE).divide(TWO).isProbablePrime(100));
            System.out.println("Safe prime gen took: " + (endTime - starTime) + "ms");
            cumulatedRuntime += endTime - starTime;
        }
        System.out.println("Average runtime new: " + (cumulatedRuntime / iterations) + "ms");

//        cumulatedRuntime = 0;
//        for(int i = 0; i < iterations; i ++){
//            long starTime = System.currentTimeMillis();
//            BigInteger safePrime = BCParameters.generateSafePrimeSimple(512, sr);
//            long endTime = System.currentTimeMillis();
//            Assert.assertTrue(safePrime.isProbablePrime(100) && safePrime.subtract(ONE).divide(TWO).isProbablePrime(100));
//            System.out.println("Safe prime gen took: " + (endTime - starTime) + "ms");
//            cumulatedRuntime += endTime - starTime;
//        }
//        System.out.println("Average runtime simple: " + (cumulatedRuntime / iterations) + "ms");
    }
}
