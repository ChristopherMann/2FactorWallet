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

import org.bitcoinj.core.*;
import org.bitcoinj.params.UnitTestParams;
import de.uni_bonn.bit.wallet_protocol.*;
import org.junit.Test;

import java.math.BigInteger;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * This class tests the classes {@link de.uni_bonn.bit.DesktopTransactionSigner} and
 * {@link de.uni_bonn.bit.PhoneTransactionSigner} which contains the Bitcoin specific logic
 * for signing Bitcoin transactions with the two-party ECDSA signature protocol.
 */
public class TransactionSignerTests extends TransactionSignerBaseTest {

    /**
     * This test signs a Bitcoin transaction with the two-party ECDSA signature protocol.
     * @throws InsufficientMoneyException
     */
    @Test
    public void testTheTransactionSigners() throws InsufficientMoneyException {
        ECKey receiverKey = convertBigIntToPrivKey(new BigInteger("100"));
        Address receiverAddress = receiverKey.toAddress(UnitTestParams.get());
        Wallet.SendRequest req = Wallet.SendRequest.to(receiverAddress, Coin.valueOf(0,3));
        req.missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;
        this.wallet.completeTx(req);

        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();

        DesktopTransactionSigner desktopSigner = new DesktopTransactionSigner(req.tx, desktopKeyShare,
                clearedCopy(phoneKeyShare), pkpDesktop, pkpPhone, desktopBCParameters, phoneBCParameters);
        PhoneTransactionSigner phoneSigner = new PhoneTransactionSigner(new TransactionInfo(req.tx), phoneKeyShare,
                clearedCopy(desktopKeyShare), pkpDesktop, pkpPhone, desktopBCParameters, phoneBCParameters);

        long startTime = System.currentTimeMillis();

        //Step 1
        SignatureParts[] signatureParts = desktopSigner.computeSignatureParts();
        //Step 2
        EphemeralValueShare[] ephemeralValueShares = phoneSigner.generateEphemeralValueShare(signatureParts);
        //Step 3
        EphemeralPublicValueWithProof[] ephemeralPublicValuesWithProof = desktopSigner.computeEphemeralPublicValue(ephemeralValueShares);
        //Step 4
        EncryptedSignatureWithProof[] encryptedSignaturesWithProof = phoneSigner.computeEncryptedSignatures(ephemeralPublicValuesWithProof);
        //Step 5
        Transaction signedTx = desktopSigner.addEncryptedSignaturesToTransaction(encryptedSignaturesWithProof);

        long endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + "ms");

        //Testing code, which throws VerificationException
        signedTx.verify();
        for(TransactionInput input : signedTx.getInputs()){
            input.verify();
        }
    }
}
