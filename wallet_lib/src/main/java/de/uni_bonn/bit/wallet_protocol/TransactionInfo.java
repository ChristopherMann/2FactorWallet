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

import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.params.RegTestParams;

import java.util.ArrayList;

/**
 * This class contains a transaction and all its connected transactions. The connected transactions are the
 * transactions referenced by the inputs of the main transaction. This class is used to transfer the connected
 * transactions to the phone wallet, which does not have access to the block chain and therefore cannot lookup the
 * connected transactions itself.
 */
public class TransactionInfo {

    byte[] transaction;
    byte[][] connectedTransactions;

    //empty constructor for serialization only
    private TransactionInfo(){}

    /**
     * Creates a transaction info from a given transaction and extracts all connected transactions. Hence, the
     * transaction's inputs must be connected.
     */
    public TransactionInfo(Transaction transaction){
        this.transaction = transaction.bitcoinSerialize();
        ArrayList<byte[]> result = new ArrayList<>();

        for(TransactionInput txInput : transaction.getInputs()){
            byte[] bytes = txInput.getConnectedOutput().getParentTransaction().bitcoinSerialize();
            result.add(bytes);
        }
        connectedTransactions = result.toArray(new byte[0][0]);
    }

    public Transaction getTransaction() {
        return new Transaction(RegTestParams.get(), transaction);
    }

    /**
     * Returns the transaction referenced by the input with the given index.
     * @param i The index of the input
     * @return The referenced transaction.
     */
    public Transaction getConnectedTransactionsForInput(int i) {
        Object obj = connectedTransactions[i];
        System.out.println("Type of value of connected transaction: " + obj.getClass().toString());
        return new Transaction(RegTestParams.get(), connectedTransactions[i]);
    }
}
