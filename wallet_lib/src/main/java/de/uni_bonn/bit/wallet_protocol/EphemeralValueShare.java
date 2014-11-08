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
 * This class defines data transfer object and represents the second message of the signature protocol. It contains a
 * public ephemeral value share.
 */
public class EphemeralValueShare {
    private byte[] Q2;


    private EphemeralValueShare(){ }

    public EphemeralValueShare(ECPoint Q2){
        setQ2(Q2);
    }

    public ECPoint getQ2() {
        return ECKey.CURVE.getCurve().decodePoint(this.Q2);
    }

    public void setQ2(ECPoint Q2) {
        this.Q2 = Q2.getEncoded(true);
    }
}
