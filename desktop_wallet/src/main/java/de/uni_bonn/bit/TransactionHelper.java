package de.uni_bonn.bit;

import org.bitcoinj.core.*;
import org.bitcoinj.params.RegTestParams;

/**
 * The class contains some helper methods for working with Bitcoin transactions.
 */
public class TransactionHelper {
	
	public static final NetworkParameters netParams = RegTestParams.get();

    public static Coin computeOverpay(Transaction transaction){
        Coin totalOutput = Coin.ZERO;
        for (TransactionOutput output : transaction.getOutputs()) {
            totalOutput = totalOutput.add(output.getValue());
        }
        Coin totalInput = Coin.ZERO;
        for (TransactionInput input : transaction.getInputs())
            if (input.getConnectedOutput() != null)
                totalInput = totalInput.add(input.getConnectedOutput().getValue());
        return totalInput.subtract(totalOutput);
    }
}
