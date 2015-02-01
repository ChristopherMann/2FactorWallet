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
package de.uni_bonn.bit.wallet_protocol;

import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.BCParameters;
import de.uni_bonn.bit.PaillierKeyPair;
import org.spongycastle.math.ec.ECPoint;

/**
 * The class defines a data transfer object and is used to transfer several setup parameters for the signature protocol.
 */
public class PairingMessage {
    PaillierKeyPair pkp;
    byte[] otherPublicKey;
    BCParameters bcParameters;
    ZKProofInit zkProofInit;

    private PairingMessage(){ }

    public PairingMessage(ECPoint otherPublicKey, PaillierKeyPair pkp, BCParameters bcParameters,
                          ZKProofInit zkProofInit) {
        if(pkp.containsPrivateKey()){
            throw new RuntimeException("Non null private key in PaillierKeyPair. This must not be the case for a pairing message!");
        }
        this.pkp = pkp;
        this.otherPublicKey = otherPublicKey.normalize().getEncoded(true);
        if(bcParameters.containsPrivateSecrets()){
            throw new RuntimeException("Non null private key in PaillierKeyPair. This must not be the case for a pairing message!");
        }
        this.bcParameters = bcParameters;
        this.zkProofInit = zkProofInit;
    }

    public ECPoint getOtherPublicKey() {
        return ECKey.CURVE.getCurve().decodePoint(otherPublicKey);
    }

    public PaillierKeyPair getPkp() {
        return pkp;
    }

    public BCParameters getBcParameters() {
        return bcParameters;
    }

    public ZKProofInit getZkProofInit() {
        return zkProofInit;
    }
}
