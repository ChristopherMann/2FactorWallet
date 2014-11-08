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
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Collection;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertPointToPubKEy;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPrivKeyToBigInt;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPubKeyToPoint;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * The base class for the protocol tests. This class only contains the setup for some parameters.
 */
@RunWith(Parameterized.class)
@Ignore
public class ProtocolBaseTest {

    @Parameterized.Parameters
    public static Collection<ECKey[]> data(){
        BigInteger nEC = ECKey.CURVE.getN();
        return Lists.newArrayList(
                new ECKey[]{ convertBigIntToPrivKey(new BigInteger("1")), convertBigIntToPrivKey(new BigInteger("2"))},
                new ECKey[]{ convertBigIntToPrivKey(nEC.subtract(new BigInteger("1"))), convertBigIntToPrivKey(nEC.subtract(new BigInteger("2")))}
        );
    }

    @Parameterized.Parameter(0)
    public ECKey desktopKeyShare;
    @Parameterized.Parameter(1)
    public ECKey phoneKeyShare;

    public ECKey commonPublicKey;

    /**
     * Hard coded BCParameters as the generation is very expensive!!!
     */
    BCParameters desktopBCParameters;
    BCParameters phoneBCParameters;

    @Before
    public void setUp() throws Exception {
        commonPublicKey = convertPointToPubKEy(
                convertPubKeyToPoint(desktopKeyShare).multiply(convertPrivKeyToBigInt(phoneKeyShare)));
        desktopBCParameters = BCParameters.generateBCParameters();
        phoneBCParameters = BCParameters.generateBCParameters2();
    }
}
