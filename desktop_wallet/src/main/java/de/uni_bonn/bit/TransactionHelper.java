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
