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

    protected BigInteger k1;
    protected BigInteger z1;
    protected BigInteger r1;
    protected BigInteger alpha;
    protected BigInteger r2;
    protected BigInteger beta;

    protected ECPoint Q2;
    protected ECPoint QCommon;

    public DesktopSigner(ECKey privateKey, ECKey otherPublicKey,  PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                         BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.privateKey = BitcoinECMathHelper.convertPrivKeyToBigInt(privateKey);
        this.otherPublicKey = BitcoinECMathHelper.convertPubKeyToPoint(otherPublicKey);
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.zkProofHelper = new MultiThreadingHelper();
    }

    public SignatureParts computeSignatureParts(){
        k1 = IntegerFunctions.randomize(nEC);
        z1 = k1.modInverse(nEC);
        r1 = pkpDesktop.generateRandomizer();
        r2 = pkpDesktop.generateRandomizer();
        //beta = pkpDesktop.encrypt(privateKey.multiply(z1).mod(nEC), r2);
        BigInteger nsquared = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> betaFuture = zkProofHelper.PowMult(pkpDesktop.getG(), privateKey.multiply(z1).mod(nEC), r2, pkpDesktop.getN(), nsquared);
        //alpha = pkpDesktop.encrypt(z1, r1);
        ForkJoinTask<BigInteger> alphaFuture = zkProofHelper.PowMult(pkpDesktop.getG(), z1, r1, pkpDesktop.getN(), nsquared);
        beta =  betaFuture.join();
        alpha = alphaFuture.join();
        return new SignatureParts(alpha, beta);
    }

    public EphemeralPublicValueWithProof computeEphemeralPublicValue(EphemeralValueShare ephemeralValueShare){
        Q2 = ephemeralValueShare.getQ2();
        // We first check that Q2 is associated with the correct curve and then we check that it is on the associated curve.
        if(! (Q2.getCurve().equals(ECKey.CURVE.getCurve()) && Q2.isValid())){
            throw new ProtocolException("The point Q provided by the desktop is invalid");
        }
        QCommon = Q2.multiply(k1).normalize();
        ECPoint QDesktop = ECKey.CURVE.getG().multiply(privateKey).normalize();
        ZKProofDesktop proof = ZKProofDesktop.generateProof(z1, privateKey.multiply(z1).mod(nEC), r1, r2, QCommon, Q2, QDesktop,
                ECKey.CURVE.getG(), alpha, beta, pkpDesktop, desktopBCParameters, zkProofHelper);
        return new EphemeralPublicValueWithProof(QCommon, proof);
    }

    public ECKey.ECDSASignature decryptEncryptedSignature(EncryptedSignatureWithProof encryptedSignature, byte[] hash){
        if(encryptedSignature.sigma.compareTo(BigInteger.ONE) < 0
                || encryptedSignature.sigma.compareTo(pkpDesktop.getN().pow(2)) >= 0){
            throw new ProtocolException("Sigma is out of bounds.");
        }
        if(encryptedSignature.alphaPrime.compareTo(BigInteger.ONE) < 0
                || encryptedSignature.alphaPrime.compareTo(pkpPhone.getN().pow(2)) >=0 ){
            throw new ProtocolException("alpha_B is out of bounds.");
        }

        BigInteger hm = new BigInteger(1, hash);
        BigInteger r = QCommon.normalize().getAffineXCoord().toBigInteger().mod(nEC);
        BigInteger nsquared = pkpDesktop.getN().pow(2);
        ForkJoinTask<BigInteger> c1 = zkProofHelper.PowMult(alpha, hm, nsquared);
        ForkJoinTask<BigInteger> c2 = zkProofHelper.PowMult(beta, r, nsquared);
        encryptedSignature.proof.verify(c1.join(), c2.join(),
                encryptedSignature.sigma, encryptedSignature.alphaPrime, ECKey.CURVE.getG(), QCommon, otherPublicKey, Q2,
                pkpDesktop, pkpPhone, phoneBCParameters, zkProofHelper);
        long start = System.currentTimeMillis();
        BigInteger s = pkpDesktop.decrypt(encryptedSignature.sigma).mod(nEC);
        System.out.println("decrypt time " + (System.currentTimeMillis() - start) + "ms");
        return new ECKey.ECDSASignature(r, s);
    }
}
