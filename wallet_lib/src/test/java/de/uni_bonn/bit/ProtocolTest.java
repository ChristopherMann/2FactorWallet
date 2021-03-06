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
import org.bitcoinj.core.Sha256Hash;
import de.uni_bonn.bit.wallet_protocol.EncryptedSignatureWithProof;
import de.uni_bonn.bit.wallet_protocol.EphemeralPublicValueWithProof;
import de.uni_bonn.bit.wallet_protocol.EphemeralValueShare;
import de.uni_bonn.bit.wallet_protocol.SignatureParts;
import org.junit.Assert;
import org.junit.Test;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;

import static de.uni_bonn.bit.BitcoinECMathHelper.*;

/**
 * This class contains a test of the two-party ECDSA signature protocol. It tests the classes
 * {@link de.uni_bonn.bit.DesktopSigner} and {@link de.uni_bonn.bit.PhoneSigner}.
 */
public class ProtocolTest extends ProtocolBaseTest {

    /**
     * This test performs a full run of the two-party ECDSA signature protocol. It tests the classes
     * It tests the classes {@link de.uni_bonn.bit.DesktopSigner} and {@link de.uni_bonn.bit.PhoneSigner} which
     * contain the implementation.
     */
    @Test
    public void test(){
        ECPoint QDesktop = convertPubKeyToPoint(desktopKeyShare);
        ECPoint QPhone = convertPubKeyToPoint(phoneKeyShare);

        byte[] message = "abcTESTMESSAGEdef".getBytes();
        Sha256Hash hash = Sha256Hash.create(message);
        byte[] hashBytes = hash.getBytes();


        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();
        DesktopSigner desktopSigner = new DesktopSigner(desktopKeyShare, convertPointToPubKEy(QPhone), pkpDesktop, pkpPhone.clearPrivateKey(), desktopBCParameters, phoneBCParameters.clearPrivate());
        PhoneSigner phoneSigner = new PhoneSigner(phoneKeyShare, convertPointToPubKEy(QDesktop), pkpDesktop.clearPrivateKey(), pkpPhone, desktopBCParameters.clearPrivate(), phoneBCParameters);

        //Step 1
        SignatureParts signatureParts = desktopSigner.computeSignatureParts();
        //Step 2
        EphemeralValueShare ephemeralValueShare = phoneSigner.generateEphemeralValueShare(signatureParts);
        //Step 3
        EphemeralPublicValueWithProof ephemeralPublicValueWithProof = desktopSigner.computeEphemeralPublicValue(ephemeralValueShare);
        //Step 4
        EncryptedSignatureWithProof encryptedSignatureWithProof = phoneSigner.computeEncryptedSignature(ephemeralPublicValueWithProof, hashBytes);
        //Step 4
        ECKey.ECDSASignature ecdsaSignature = desktopSigner.decryptEncryptedSignature(encryptedSignatureWithProof, hashBytes);

        Assert.assertTrue(commonPublicKey.verify(hash, ecdsaSignature));
    }
}
