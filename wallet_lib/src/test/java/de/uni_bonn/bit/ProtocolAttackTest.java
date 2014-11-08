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
package de.uni_bonn.bit;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import com.google.common.collect.Lists;
import com.google.common.math.DoubleMath;
import de.uni_bonn.bit.wallet_protocol.EncryptedSignatureWithProof;
import de.uni_bonn.bit.wallet_protocol.EphemeralPublicValueWithProof;
import de.uni_bonn.bit.wallet_protocol.EphemeralValueShare;
import de.uni_bonn.bit.wallet_protocol.SignatureParts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;
import java.util.List;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertPointToPubKEy;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPrivKeyToBigInt;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPubKeyToPoint;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * This class contains the implementations of two basic attacks on the two-party ECDSA signature protocol. The attacks
 * must not succeed if the protocol is correctly implemented.
 */
public class ProtocolAttackTest {

    ECKey desktopKeyShare = convertBigIntToPrivKey(new BigInteger("41"));
    ECKey phoneKeyShare = convertBigIntToPrivKey(new BigInteger("42"));

    ECKey commonPublicKey;
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;

    @Before
    public void setUp() {
        commonPublicKey = convertPointToPubKEy(
                convertPubKeyToPoint(desktopKeyShare).multiply(convertPrivKeyToBigInt(phoneKeyShare)));
        desktopBCParameters = BCParameters.generateBCParameters();
        phoneBCParameters = BCParameters.generateBCParameters2();
    }

    /**
     * This test tries to trick the phone into singing something completely different then it thinks by sending
     * incorrectly constructed alpha and beta to the phone. This attack should not succeed as the zero-knowledge
     * proof Pi_A proofs to the phone that alpha and beta are correct.
     */
    @Test(expected = ProtocolException.class)
    public void attackOnPhoneSignerTest(){
        BigInteger nEC = ECKey.CURVE.getN();
        byte[] benignHash = Sha256Hash.create("---Benign Message---".getBytes()).getBytes();
        final BigInteger benignHashInt = new BigInteger(1, benignHash);
        Sha256Hash maliciousHash = Sha256Hash.create("---Malicious Message---".getBytes());
        final BigInteger maliciousHashInt = new BigInteger(1, maliciousHash.getBytes());

        ECPoint QDesktop = convertPubKeyToPoint(desktopKeyShare);
        ECPoint QPhone = convertPubKeyToPoint(phoneKeyShare);

        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();
        DesktopSigner desktopSigner = new DesktopSigner(desktopKeyShare, convertPointToPubKEy(QPhone), pkpDesktop, pkpPhone,
                desktopBCParameters, phoneBCParameters){
            @Override
            public SignatureParts computeSignatureParts() {
                k1 = IntegerFunctions.randomize(nEC);
                z1 = k1.modInverse(nEC);
                r1 = pkpDesktop.generateRandomizer();
                alpha = pkpDesktop.encrypt(z1.multiply(benignHashInt.modInverse(nEC)).multiply(maliciousHashInt).mod(nEC), r1);
                r2 = pkpDesktop.generateRandomizer();
                beta = pkpDesktop.encrypt(privateKey.multiply(z1).mod(nEC), r2);
                return new SignatureParts(alpha, beta);
            }

            @Override
            public ECKey.ECDSASignature decryptEncryptedSignature(EncryptedSignatureWithProof encryptedSignature, byte[] hash) {
                BigInteger r = QCommon.normalize().getAffineXCoord().toBigInteger().mod(nEC);
                BigInteger s = pkpDesktop.decrypt(encryptedSignature.sigma).mod(nEC);
                return new ECKey.ECDSASignature(r, s);
            }
        };
        PhoneSigner phoneSigner = new PhoneSigner(phoneKeyShare, convertPointToPubKEy(QDesktop), pkpDesktop, pkpPhone,
                desktopBCParameters, phoneBCParameters);
        //Step 1
        SignatureParts signatureParts = desktopSigner.computeSignatureParts();
        //Step 2
        EphemeralValueShare ephemeralValueShare = phoneSigner.generateEphemeralValueShare(signatureParts);
        //Step 3
        EphemeralPublicValueWithProof ephemeralPublicValueWithProof = desktopSigner.computeEphemeralPublicValue(ephemeralValueShare);
        //Step 4
        EncryptedSignatureWithProof encryptedSignatureWithProof = phoneSigner.computeEncryptedSignature(ephemeralPublicValueWithProof, benignHash);
        //Step 4
        ECKey.ECDSASignature ecdsaSignature = desktopSigner.decryptEncryptedSignature(encryptedSignatureWithProof, maliciousHash.getBytes());

        Assert.assertFalse("Attack successful! The phone signer has been tricked into creating a signature for an unknown hash value.",
                commonPublicKey.verify(maliciousHash, ecdsaSignature));
    }

    /**
     * This test tries to find out the length of the phone's private by analyzing the encrypted signature sigma.
     * This attack should not succeed as the phone adds some additional randomization to the encrypted signature.
     * The randomization should prevent such an information leak.
     */
    @Test
    public void attackOnPhoneSignerTest2(){
        BigInteger nEC = ECKey.CURVE.getN();
        byte[] hash = Sha256Hash.create("---Benign Message---".getBytes()).getBytes();

        ECKey phoneKeySmall = convertBigIntToPrivKey(new BigInteger("1"));
        ECPoint QPhoneSmall = convertPubKeyToPoint(phoneKeySmall);

        ECKey phoneKeyLarge = convertBigIntToPrivKey(nEC.subtract(BigInteger.ONE));
        ECPoint QPhoneLarge = convertPubKeyToPoint(phoneKeyLarge);

        ECPoint QDesktop = convertPubKeyToPoint(desktopKeyShare);

        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();

        //Phone uses a small key
        List<Integer> bitLengthsSmall = Lists.newArrayList(10);
        for(int i = 1; i < 10; i++){
            DesktopSigner desktopSigner = new DesktopSigner(desktopKeyShare, convertPointToPubKEy(QPhoneSmall),
                    pkpDesktop, pkpPhone, desktopBCParameters, phoneBCParameters);
            PhoneSigner phoneSigner = new PhoneSigner(phoneKeySmall, convertPointToPubKEy(QDesktop), pkpDesktop, pkpPhone,
                    desktopBCParameters, phoneBCParameters);
            //Step 1
            SignatureParts signatureParts = desktopSigner.computeSignatureParts();
            //Step 2
            EphemeralValueShare ephemeralValueShare = phoneSigner.generateEphemeralValueShare(signatureParts);
            //Step 3
            EphemeralPublicValueWithProof ephemeralPublicValueWithProof = desktopSigner.computeEphemeralPublicValue(ephemeralValueShare);
            //Step 4
            EncryptedSignatureWithProof encryptedSignatureWithProof = phoneSigner.computeEncryptedSignature(ephemeralPublicValueWithProof, hash);
            bitLengthsSmall.add(pkpDesktop.decrypt(encryptedSignatureWithProof.sigma).bitLength());
        }

        //Phone uses a large key
        List<Integer> bitLengthsLarge = Lists.newArrayList(10);
        for(int i = 1; i < 10; i++){
            DesktopSigner desktopSigner = new DesktopSigner(desktopKeyShare, convertPointToPubKEy(QPhoneLarge),
                    pkpDesktop, pkpPhone, desktopBCParameters, phoneBCParameters);
            PhoneSigner phoneSigner = new PhoneSigner(phoneKeyLarge, convertPointToPubKEy(QDesktop), pkpDesktop, pkpPhone,
                    desktopBCParameters, phoneBCParameters);
            //Step 1
            SignatureParts signatureParts = desktopSigner.computeSignatureParts();
            //Step 2
            EphemeralValueShare ephemeralValueShare = phoneSigner.generateEphemeralValueShare(signatureParts);
            //Step 3
            EphemeralPublicValueWithProof ephemeralPublicValueWithProof = desktopSigner.computeEphemeralPublicValue(ephemeralValueShare);
            //Step 4
            EncryptedSignatureWithProof encryptedSignatureWithProof = phoneSigner.computeEncryptedSignature(ephemeralPublicValueWithProof, hash);
            bitLengthsLarge.add(pkpDesktop.decrypt(encryptedSignatureWithProof.sigma).bitLength());
        }

        double smallMean = DoubleMath.mean(bitLengthsSmall);
        double largeMean = DoubleMath.mean(bitLengthsLarge);

        System.out.printf("smallKey: %4.2f <-> largeKey: %4.2f", smallMean, largeMean);

        Assert.assertTrue("Attack successful! Desktop signer can see the length of the phone signer's key.",
                Math.abs(smallMean - largeMean) < 3);
    }

}
