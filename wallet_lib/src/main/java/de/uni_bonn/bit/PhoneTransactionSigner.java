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
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.script.Script;
import de.uni_bonn.bit.wallet_protocol.*;

import java.util.HashMap;
import java.util.Map;

/**
 * This class implements the phone's logic for signing a Bitcoin transaction with the two-party ECDSA signature
 * protocol. This class only contains the Bitcoin-specific logic and uses one or more instances of the class
 * {@link de.uni_bonn.bit.PhoneSigner} to create ECDSA signatures for the transaction inputs with the help of
 * the two-party ECDSA signature protocol. This class does not return any result. (The signed transaction is
 * returned by the {@link de.uni_bonn.bit.DesktopTransactionSigner}).
 */
public class PhoneTransactionSigner {
    PaillierKeyPair pkpDesktop;
    PaillierKeyPair pkpPhone;
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;
    ECKey privateKey;
    ECKey otherPublicKey;
    TransactionInfo transactionInfo;

    Map<Integer,PhoneSigner> hashSignerMap = new HashMap<>();


    public PhoneTransactionSigner(TransactionInfo transactionInfo, ECKey privateKey, ECKey otherPublicKey,
                                  PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone,
                                  BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.transactionInfo = transactionInfo;
        this.privateKey = privateKey;
        this.otherPublicKey = otherPublicKey;
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters = phoneBCParameters;
    }

    public EphemeralValueShare[] generateEphemeralValueShare(SignatureParts[] signatureParts){
        if(signatureParts.length != transactionInfo.getTransaction().getInputs().size()){
            throw new ProtocolException("The number of signature parts does not fit the number of transaction inputs.");
        }
        EphemeralValueShare[] result = new EphemeralValueShare[signatureParts.length];
        for(int i = 0; i < signatureParts.length; i++){
            PhoneSigner phoneSigner = new PhoneSigner(privateKey, otherPublicKey, pkpDesktop, pkpPhone,
                    desktopBCParameters, phoneBCParameters);
            hashSignerMap.put(i, phoneSigner);
            result[i] = phoneSigner.generateEphemeralValueShare(signatureParts[i]);
        }
        return result;
    }

    public EncryptedSignatureWithProof[] computeEncryptedSignatures(EphemeralPublicValueWithProof[] ephemeralPublicValuesWithProof){
        EncryptedSignatureWithProof[] result = new EncryptedSignatureWithProof[transactionInfo.getTransaction().getInputs().size()];
        for(int i = 0; i < ephemeralPublicValuesWithProof.length; i++) {
            EphemeralPublicValueWithProof valueWithProof = ephemeralPublicValuesWithProof[i];
            if (valueWithProof != null) {
                TransactionInput transactionInput = transactionInfo.getTransaction().getInput(i);
                long outputIndex = transactionInput.getOutpoint().getIndex();
                Script scriptPubKey = transactionInfo.getConnectedTransactionsForInput(i).getOutput((int) outputIndex).getScriptPubKey();
                byte[] hashToSign = transactionInfo.getTransaction().hashForSignature(i,
                        scriptPubKey, Transaction.SigHash.ALL, false).getBytes();
                result[i] = hashSignerMap.get(i).computeEncryptedSignature(valueWithProof, hashToSign);
            }
        }
        return result;
    }
}
