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

import org.apache.avro.reflect.Stringable;

import java.math.BigInteger;

/**
 * This class defines data transfer object and represents the last message in the signature protocol. It contains the
 * encrypted signature and a zero-knowledge proof.
 */
public class EncryptedSignatureWithProof {

    @Stringable
    public BigInteger sigma;
    @Stringable
    public BigInteger alphaPrime;
    public ZKProofPhone proof;

    public EncryptedSignatureWithProof(){}

    public EncryptedSignatureWithProof(BigInteger sigma, BigInteger alphaPrime, ZKProofPhone proof) {
        this.sigma = sigma;
        this.alphaPrime = alphaPrime;
        this.proof = proof;
    }
}
