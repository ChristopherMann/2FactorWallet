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
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import de.uni_bonn.bit.wallet_protocol.*;

import static de.uni_bonn.bit.BitcoinECMathHelper.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * This class implements the desktop's logic for signing a Bitcoin transaction with the two-party ECDSA signature
 * protocol. This class only contains the Bitcoin-specific logic and uses one or more instances of the class
 * {@link de.uni_bonn.bit.DesktopSigner} to create ECDSA signatures for the transaction inputs with the help of
 * the two-party ECDSA signature protocol. In the end, this class returns a correctly signed Bitcoin transaction.
 */
public class DesktopTransactionSigner {

    ECKey privateKey;
    ECKey otherPublicKey;
    PaillierKeyPair pkpDesktop;
    PaillierKeyPair pkpPhone;
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;
    Map<String,ECKey> keyShareMap;
    //Address private key map;
    Transaction transaction;
    ECKey commonPublicKey;

    Map<Integer,DesktopSigner> hashSignerMap = new HashMap<>();

    public DesktopTransactionSigner(Transaction transaction, ECKey privateKey, ECKey otherPublicKey, PaillierKeyPair pkpDesktop,
                                    PaillierKeyPair pkpPhone, BCParameters desktopBCParameters, BCParameters phoneBCParameters) {
        this.privateKey = privateKey;
        this.otherPublicKey = otherPublicKey;
        this.pkpDesktop = pkpDesktop;
        this.pkpPhone = pkpPhone;
        this.desktopBCParameters = desktopBCParameters;
        this.phoneBCParameters =  phoneBCParameters;
        this.transaction = transaction;
        commonPublicKey = convertPointToPubKEy(convertPubKeyToPoint(otherPublicKey)
                .multiply(convertPrivKeyToBigInt(privateKey))
                .normalize());
    }

    public SignatureParts[] computeSignatureParts(){
        SignatureParts[] sigParts = new SignatureParts[transaction.getInputs().size()];
        for(int i = 0; i < transaction.getInputs().size(); i++){
            TransactionInput transactionInput = transaction.getInput(i);
            TransactionSignature transactionSignature = retrieveTransactionSignatureFromScriptSig(transactionInput.getScriptSig());
            if(isDummySignature(transactionSignature)){
                //unsigned input -> we will try to sign it using the two party protocol
                Script scriptPubKey = transactionInput.getConnectedOutput().getScriptPubKey();
                if(Arrays.equals(scriptPubKey.getPubKeyHash(), commonPublicKey.getPubKeyHash())){
                    //The input uses an output which can be spent with our two party authentication
                    DesktopSigner hashSigner = new DesktopSigner(privateKey, otherPublicKey, pkpDesktop,
                            pkpPhone, desktopBCParameters, phoneBCParameters);
                    hashSignerMap.put(i, hashSigner);
                    sigParts[i] = hashSigner.computeSignatureParts();
                }
            }
        }
        return sigParts;
    }

    public EphemeralPublicValueWithProof[] computeEphemeralPublicValue(EphemeralValueShare[] ephemeralValueShares){
        if(ephemeralValueShares.length != transaction.getInputs().size()){
            throw new ProtocolException("The number of ephemeral value shares does not fit the number of inputs.");
        }
        EphemeralPublicValueWithProof[] result = new EphemeralPublicValueWithProof[ephemeralValueShares.length];
        for(int i = 0; i < ephemeralValueShares.length; i++){
            result[i] = hashSignerMap.get(i).computeEphemeralPublicValue(ephemeralValueShares[i]);
        }
        return result;
    }

    public Transaction addEncryptedSignaturesToTransaction(EncryptedSignatureWithProof[] encryptedSignatureMap){
        for(Map.Entry<Integer, DesktopSigner> entry : hashSignerMap.entrySet()){
            int i = entry.getKey();
            DesktopSigner hashSigner = entry.getValue();

            EncryptedSignatureWithProof encSignature = encryptedSignatureMap[i];
            if(encSignature == null)
                throw new ProtocolException("An encrypted signature is missing!");
            TransactionInput transactionInput = transaction.getInput(i);
            Script scriptPubKey = transactionInput.getConnectedOutput().getScriptPubKey();
            byte[] hash = transaction.hashForSignature(i,
                    scriptPubKey, Transaction.SigHash.ALL, false).getBytes();
            ECKey.ECDSASignature ecdsaSignature = hashSigner.decryptEncryptedSignature(encSignature, hash);
            TransactionSignature txSignature = new TransactionSignature(ecdsaSignature, Transaction.SigHash.ALL, false);
            transaction.getInput(i).setScriptSig(replaceSignatureInScriptSig(transactionInput.getScriptSig(), txSignature));
        }
        return transaction;
    }

    public static TransactionSignature retrieveTransactionSignatureFromScriptSig(Script script) throws ScriptException{
        if(! isStandardScriptSig(script))
            throw new ScriptException("Script is not a standard script sig.");
        try{
            return TransactionSignature.decodeFromBitcoin(script.getChunks().get(0).data, false);
        }catch(VerificationException ex){
            throw new ScriptException("Failed to parse signature from the script sig");
        }
    }

    public static boolean isDummySignature(TransactionSignature signature){
        TransactionSignature dummySignature = TransactionSignature.dummy();
        return signature.r.equals(dummySignature.r) && signature.s.equals(dummySignature.s);
    }

    public static Script replaceSignatureInScriptSig(Script scriptSig, TransactionSignature txSignature){
        if(! isStandardScriptSig(scriptSig))
            throw new ScriptException("Script is not a standard script sig.");
        byte[] newSigBytes = txSignature.encodeToBitcoin();
        byte[] pubKeyBytes = scriptSig.getPubKey();
        ScriptBuilder sb = new ScriptBuilder();
        sb.data(newSigBytes);
        sb.data(pubKeyBytes);
        Script newScript = sb.build();
        return newScript;
    }

    /**
     * Checks, whether the provided script has the layout of  a standard script sig. The tests are only heuristic.
     * @param scriptSig
     * @return
     */
    public static boolean isStandardScriptSig(Script scriptSig){
        List<ScriptChunk> chunks = scriptSig.getChunks();
        if(chunks.size() != 2)
            return false;
        if(chunks.get(0).isOpCode() || chunks.get(1).isOpCode())
            return false;
        return true;
    }
}
