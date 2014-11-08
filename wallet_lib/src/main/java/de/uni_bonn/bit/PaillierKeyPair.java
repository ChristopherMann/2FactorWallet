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
import org.apache.avro.reflect.Nullable;
import org.apache.avro.reflect.Stringable;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class represents a key pair for the Paillier crypto system. It can contain either a complete key pair consisting
 * of a private key and the corresponding public key or only the public key. This class can generate key pairs, perform
 * encryption and decryption, and apply homomorphic operations to the cipher texts.
 */
public class PaillierKeyPair {

    @Stringable BigInteger n;
    @Stringable BigInteger g;
    @Stringable @Nullable
    BigInteger lambda; //PRIVATE KEY
    @Stringable @Nullable
    BigInteger my; //PRIVATE KEY

    public PaillierKeyPair() {}

    public PaillierKeyPair(int securityParameter) {
        SecureRandom sr = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(securityParameter / 2 + 1, sr);
        BigInteger q = BigInteger.probablePrime(securityParameter / 2 + 1, sr);
        n = p.multiply(q);
        lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        BigInteger nsquare = n.multiply(n);
        do{
            g = IntegerFunctions.randomize(nsquare);
        }while(! L(g.modPow(lambda, nsquare)).gcd(n).equals(BigInteger.ONE));

        my = L(g.modPow(lambda, nsquare)).modInverse(n);
    }

    public BigInteger encrypt(BigInteger message){
        if(message.compareTo(n) >= 0)
            throw new IllegalArgumentException("The message is to large for the group.");
        BigInteger r = generateRandomizer();
        return encrypt(message, r);
    }

    public BigInteger generateRandomizer(){
        return IntegerFunctions.randomize(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    public BigInteger encrypt(BigInteger message, BigInteger r){
        if(message.compareTo(n) >= 0)
            throw new IllegalArgumentException("The message is to large for the group.");
        if(r.compareTo(n) >= 0)
            throw new IllegalArgumentException("The randomizer r is to large for the group.");
        BigInteger nsquare = n.multiply(n);
        BigInteger c = g.modPow(message, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
        return c;
    }

    public BigInteger decrypt(BigInteger ciphertext){
        BigInteger nsquare = n.multiply(n);
        if(ciphertext.compareTo(nsquare) >= 0)
            throw new IllegalArgumentException("The cipher text is to large.");
        BigInteger m = L(ciphertext.modPow(lambda, nsquare)).multiply(my).mod(n);
        return m;
    }

    public BigInteger multiplyWithScalar(BigInteger c, BigInteger scalar){
        return c.modPow(scalar, n.multiply(n));
    }

    public BigInteger add(BigInteger a, BigInteger b){
        return a.multiply(b).mod(n.multiply(n));
    }

    public static BigInteger lcm(BigInteger a, BigInteger b){
        return a.divide(a.gcd(b)).multiply(b);
    }

    public BigInteger L(BigInteger u){
        return u.subtract(BigInteger.ONE).divide(n);
    }

    /**
     * Returns a copy of this key pair which only contains the public key. All private information has been removed.
     */
    public PaillierKeyPair clearPrivateKey(){
        PaillierKeyPair result = new PaillierKeyPair();
        result.n = this.n;
        result.g = this.g;
        //private key part to null
        result.lambda = null;
        result.my = null;
        return result;
    }

    public boolean containsPrivateKey(){
        return lambda != null || my != null;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getG() {
        return g;
    }

    public static PaillierKeyPair generatePaillierKeyPair(){
        //The protocol requires a minimal bitlength of |n|*9 (in ZKProof section), using |n|*10
        int minBitLength = ECKey.CURVE.getN().bitLength() * 10;
        //This is RSA modules -> we want at least 2048 bits for security
        int secParam = 2048 > minBitLength ? 2048 : minBitLength;
        return new PaillierKeyPair(secParam);
    }
}
