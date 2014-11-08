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

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

/**
 * This class defines data transfer object and represents the third message of the signature protocol. It contains the
 * public ephemeral value and a zero-knowledge proof.
 */
public class EphemeralPublicValueWithProof {
    private byte[] Q;
    private ZKProofDesktop proof;

    private EphemeralPublicValueWithProof(){ }

    public EphemeralPublicValueWithProof(ECPoint Q, ZKProofDesktop proof) {
        this.Q = Q.getEncoded(true);
        this.proof = proof;
    }

    public ECPoint getQ() {
        return ECKey.CURVE.getCurve().decodePoint(this.Q);
    }

    public ZKProofDesktop getProof() {
        return proof;
    }
}
