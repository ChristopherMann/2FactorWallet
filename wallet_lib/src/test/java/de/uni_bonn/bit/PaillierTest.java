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

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Collection;
import java.util.List;

/**
 * This class contains the unit tests for the implementation of the Paillier crypto system.
 */
@RunWith(Parameterized.class)
public class PaillierTest {

    @Parameterized.Parameters(name="{index}: m1={0}, m2={1}, s={2}")
    public static Collection<BigInteger[]> data(){
        List<BigInteger[]> result = Lists.newLinkedList();
        List<BigInteger> values = Lists.newArrayList(BigInteger.ZERO, BigInteger.ONE, new BigInteger("42"), pkp.n.subtract(BigInteger.ONE));
        for(BigInteger m1 : values)
        for(BigInteger m2 : values)
        for(BigInteger s : values)
        result.add(new BigInteger[]{m1, m2, s});
        return result;
    }

    static PaillierKeyPair pkp = new PaillierKeyPair(100);

    @Parameterized.Parameter(value=0)
    public BigInteger message1;
    @Parameterized.Parameter(value=1)
    public BigInteger message2;
    @Parameterized.Parameter(value=2)
    public BigInteger scalar;

    @Test
    public void EncryptDecryptTest() {
        PaillierKeyPair clearedPkp = pkp.clearPrivateKey();
        Assert.assertEquals(message1, pkp.decrypt(clearedPkp.encrypt(message1)));
    }

    @Test
    public void HomomorphyMultiplicationTest() {
        PaillierKeyPair clearedPkp = pkp.clearPrivateKey();
        BigInteger c = clearedPkp.encrypt(message1);
        Assert.assertEquals(message1.multiply(scalar).mod(pkp.n), pkp.decrypt(clearedPkp.multiplyWithScalar(c, scalar)));
    }

    @Test
    public void HomomorphyAdditionTest() {
        PaillierKeyPair clearedPkp = pkp.clearPrivateKey();
        BigInteger c1 = clearedPkp.encrypt(message1);
        BigInteger c2 = clearedPkp.encrypt(message2);
        Assert.assertEquals(message1.add(message2).mod(pkp.n), pkp.decrypt(clearedPkp.add(c1, c2)));
    }

    @Test
    public void CombinedTest() {
        PaillierKeyPair clearedPkp = pkp.clearPrivateKey();
        BigInteger c1 = clearedPkp.encrypt(message1);
        BigInteger c2 = clearedPkp.encrypt(message2);
        Assert.assertEquals((message1.add(message2)).multiply(scalar).mod(pkp.n),
                pkp.decrypt(clearedPkp.add(clearedPkp.multiplyWithScalar(c1, scalar), clearedPkp.multiplyWithScalar(c2, scalar))));
    }
}
