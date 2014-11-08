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

import org.bitcoinj.core.ECKey;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class contains helper methods to convert between ECKey objects and their mathematical representations (ECPoint
 * and BigInteger).
 */
public class BitcoinECMathHelper {

    public static BigInteger convertPrivKeyToBigInt(ECKey ecKey){
        checkArgument(ecKey.hasPrivKey(), "Private key expected, but ecKey only contains a public key.");
        return new BigInteger(1, ecKey.getPrivKeyBytes());
    }

    public static ECKey convertBigIntToPrivKey(BigInteger bigInt){
        checkArgument(bigInt.compareTo(BigInteger.ONE) >= 0, "A private key must be >= 1");
        checkArgument(bigInt.compareTo(ECKey.CURVE.getN()) < 0, "A private key must be <= N_EC");
        return ECKey.fromPrivate(bigInt);
    }

    public static ECPoint convertPubKeyToPoint(ECKey ecKey){
        return ECKey.CURVE.getCurve().decodePoint(ecKey.getPubKey()).normalize();
    }

    public static ECKey convertPointToPubKEy(ECPoint point){
        return ECKey.fromPublicOnly(point);
    }
}
