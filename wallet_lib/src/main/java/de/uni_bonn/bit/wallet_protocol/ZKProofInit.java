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

import de.uni_bonn.bit.BCParameters;
import de.uni_bonn.bit.ProtocolException;
import org.apache.avro.reflect.Stringable;
import org.spongycastle.pqc.math.ntru.euclid.BigIntEuclidean;

import java.math.BigInteger;

public class ZKProofInit {

    @Stringable
    private BigInteger gRoot;
    @Stringable
    private BigInteger hRoot;
    /**
     * Generates a zero-knowledge proof which proves that bcParameters.g and bcParameters.h are quadratic residues,
     * which is implies that they are part of the same cyclic sub group.
     * @param bcParameters
     * @param id An id which identifies the proof instance. The result should depend on the proof it is used for to
     *           prevent replay attacks.
     * @return
     */
    public static ZKProofInit generate(BCParameters bcParameters, String id){
        ZKProofInit result = new ZKProofInit();
        result.gRoot = squareRoot(bcParameters.getH(), bcParameters.getP(), bcParameters.getQ());
        result.hRoot = squareRoot(bcParameters.getG(), bcParameters.getP(), bcParameters.getQ());
        return result;
    }

    /**
     * Verifies this zk proof for the given bcParameters.
     * @param bcParameters
     * @param id
     */
    public void verify(BCParameters bcParameters, String id){
        BigInteger gRootSquared = gRoot.pow(2).mod(bcParameters.getN());
        BigInteger hRootSquared = hRoot.pow(2).mod(bcParameters.getN());

        if(! bcParameters.getH().equals(gRootSquared) || ! bcParameters.getG().equals(hRootSquared)){
            throw new ProtocolException("Verification of ZKProof init with id  " + id + " failed.");
        }
    }

    private static BigInteger squareRoot(BigInteger x, BigInteger p, BigInteger q){
        BigInteger four = new BigInteger("4");
        BigInteger rp = x.modPow(p.add(BigInteger.ONE).divide(four), p);
        BigInteger rq = x.modPow(q.add(BigInteger.ONE).divide(four), q);

        BigIntEuclidean euclidp = BigIntEuclidean.calculate(p, q);
        BigIntEuclidean euclidq = BigIntEuclidean.calculate(q, p);

        BigInteger ep = euclidp.y.multiply(q);
        BigInteger eq = euclidq.y.multiply(p);

        BigInteger r = rp.multiply(ep).add(rq.multiply(eq)).mod(p.multiply(q));

        return r;
    }
}
