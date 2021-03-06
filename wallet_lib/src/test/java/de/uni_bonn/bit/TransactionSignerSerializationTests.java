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
import org.apache.avro.ipc.NettyServer;
import org.apache.avro.ipc.NettyTransceiver;
import org.apache.avro.ipc.reflect.ReflectRequestor;
import org.apache.avro.ipc.reflect.ReflectResponder;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.Map;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * This class performs the same tests as {@link de.uni_bonn.bit.TransactionSignerTests}, but all messages
 * are exchanged via serialization. This class primarily checks that the Avro serialization used for the
 * communication between desktop and phone can successfully (de)serialize all objects required for the
 * protocol.
 */
public class TransactionSignerSerializationTests extends TransactionSignerBaseTest {

    /**
     * Similar to {@link TransactionSignerTests#testTheTransactionSigners()}, this test signs a
     * Bitcoin transaction with the two-party ECDSA signature protocol. All messages exchanged between
     * the {@link de.uni_bonn.bit.DesktopTransactionSigner} and the {@link de.uni_bonn.bit.PhoneTransactionSigner}
     * are serialized and sent over the local loopback. This test primarily exists to check that the
     * (de)serialization with avro works correctly.
     * @throws InsufficientMoneyException
     */
    @Test
    public void testTheTransactionSigners() throws InsufficientMoneyException, IOException, InterruptedException {
        ECKey receiverKey = convertBigIntToPrivKey(new BigInteger("100"));
        Address receiverAddress = receiverKey.toAddress(UnitTestParams.get());
        Wallet.SendRequest req = Wallet.SendRequest.to(receiverAddress, Coin.valueOf(0,3));
        req.missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;
        this.wallet.completeTx(req);

        PaillierKeyPair pkpDesktop = PaillierKeyPair.generatePaillierKeyPair();
        PaillierKeyPair pkpPhone = PaillierKeyPair.generatePaillierKeyPair();

        WalletProtocolTestImpl impl = new WalletProtocolTestImpl(req.tx, desktopKeyShare, clearedCopy(phoneKeyShare),
                pkpDesktop, pkpPhone.clearPrivateKey(), desktopBCParameters, phoneBCParameters.clearPrivate());

        NettyServer server = new NettyServer(new ReflectResponder(IWalletProtocol.class,
                impl), new InetSocketAddress(20000));

        NettyTransceiver transceiver = new NettyTransceiver(new InetSocketAddress(20000));
        IWalletProtocol proxy = ReflectRequestor.getClient(IWalletProtocol.class, transceiver);

        TransactionInfo txInfo = proxy.fetchTransactionInfo();
        PhoneTransactionSigner signer = new PhoneTransactionSigner(txInfo, phoneKeyShare, clearedCopy(desktopKeyShare),
                pkpDesktop.clearPrivateKey(), pkpPhone, desktopBCParameters.clearPrivate(), phoneBCParameters);

        SignatureParts[] signatureParts = proxy.getSignatureParts();
        EphemeralValueShare[] ephemeralValueShares = signer.generateEphemeralValueShare(signatureParts);

        EphemeralPublicValueWithProof[] ephemeralPublicValuesWithProof = proxy.getEphemeralPublicValuesWithProof(ephemeralValueShares);
        EncryptedSignatureWithProof[] encryptedSignaturesWithProof = signer.computeEncryptedSignatures(ephemeralPublicValuesWithProof);
        proxy.sendEncryptedSignatures(encryptedSignaturesWithProof);

        Thread.sleep(1000);
        Transaction signedTx = impl.transaction;
        server.close();

        //Testing code, which throws VerificationException
        signedTx.verify();
        for(TransactionInput input : signedTx.getInputs()){
            input.verify();
        }
    }

    public static class WalletProtocolTestImpl implements IWalletProtocol {

        Transaction transaction;
        Map<String, ECKey> keyShareMap;
        DesktopTransactionSigner signer;

        public WalletProtocolTestImpl(Transaction transaction, ECKey privateKey, ECKey otherPublicKey,
                                      PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone, BCParameters desktopBCParameters,
                                      BCParameters phoneBCParameters) {
            this.transaction = transaction;
            this.keyShareMap = keyShareMap;
            this.signer = new DesktopTransactionSigner(transaction, privateKey, otherPublicKey, pkpDesktop, pkpPhone,
                    desktopBCParameters, phoneBCParameters);
        }

        @Override
        public TransactionInfo fetchTransactionInfo() {
            return new TransactionInfo(transaction);
        }

        @Override
        public SignatureParts[] getSignatureParts() {
            return signer.computeSignatureParts();
        }

        @Override
        public EphemeralPublicValueWithProof[] getEphemeralPublicValuesWithProof(EphemeralValueShare[] ephemeralValueShares) {
            return signer.computeEphemeralPublicValue(ephemeralValueShares);
        }

        @Override
        public boolean sendEncryptedSignatures(EncryptedSignatureWithProof[] encryptedSignatures) {
            transaction = signer.addEncryptedSignaturesToTransaction(encryptedSignatures);
            return true;
        }
    }


}
