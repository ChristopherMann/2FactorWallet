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

import org.bitcoinj.core.ECKey;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.RecursiveTask;

/**
 * This class contains several methods to perform mathematical operations. Most importantly, it contains methods
 * which perform expensive ECPoint and BigInteger operations with multi threading. Java's ForkJoinTask is used for the
 * multi threading and this class keeps an instance of ForkJoinPool to execute the tasks.
 */
public class MultiThreadingHelper {
    private static final BigInteger nEC = ECKey.CURVE.getN();
    public static BigInteger hash(String id, Object... data){
        System.out.println("hash() called with parameters:");
        System.out.println(id);
        SHA512Digest digest = new SHA512Digest();
        digest.update(id.getBytes(), 0, id.getBytes().length);
        for(Object obj : data){
            if( obj instanceof ECPoint){
                byte[] pointData = ((ECPoint) obj).normalize().getEncoded(true);
                System.out.println(obj.toString());
                digest.update(pointData, 0, pointData.length);
            }else if (obj instanceof BigInteger){
                byte[] bigIntData = ((BigInteger) obj).toByteArray();
                System.out.println(obj.toString());
                digest.update(bigIntData, 0, bigIntData.length);
            }else{
                throw new RuntimeException("Wrong type in hash function: " + obj.getClass().toString());
            }
        }
        byte[] resultBytes = new byte[64];
        digest.doFinal(resultBytes, 0);
        return new BigInteger(1, resultBytes).mod(nEC);
    }

    public static void dumpBitLengthOfValues(BigInteger... data) {
        System.out.println("Bitlengths:");
        for (BigInteger bigInt : data) {
            System.out.println(bigInt.bitLength());
        }
    }

    public ECPoint[] multiplyPointsWithScalars(BigInteger[] scalars, ECPoint[] points){
        ECPoint[] results = new ECPoint[points.length];
        for(int i = 0; i < points.length; i++){
            results[i] = points[i].multiply(scalars[i]);
        }
        return results;
    }

    private ForkJoinPool pool;
    private ForkJoinPool getPool(){
        if(pool == null){
            pool = new ForkJoinPool();
        }
        return pool;
    }

    /**
     * Sums up scalar multiplied points.
     * @param values a, P, b, Q, c, R
     * @return a*P+b*Q+c*R
     */
    public ForkJoinTask<ECPoint> pointMultAdd(Object... values){
        return getPool().submit(new PointMultAddTask(values));
    }

    /**
     * Multiplies several modpowed numbers.
     * @param values a,b,c,d,e,f,q
     * @return a^b*c^d*e^f mod q
     */
    public ForkJoinTask<BigInteger> PowMult(Object... values){
        return getPool().submit(new PowMultTask(values));
    }

    public static class PointMultAddTask extends RecursiveTask<ECPoint> {

        final Object[] values;
        boolean normalize = true;

        public PointMultAddTask(Object... values) {
            this.values = values;
        }

        @Override
        protected ECPoint compute() {
            if(values.length == 2){
                long msStart = System.currentTimeMillis();
                final BigInteger scalar = (BigInteger) values[0];
                final ECPoint point = (ECPoint) values[1];
                ECPoint result = point.multiply(scalar.mod(nEC));
                if(normalize){
                    result = result.normalize();
                }
                return result;
            }else{
                List<ForkJoinTask<ECPoint>> futures = new ArrayList<>();
                long msStart = System.currentTimeMillis();
                for(int i = 2; i < values.length; i += 2){
                    PointMultAddTask pma = new PointMultAddTask(values[i], values[i+1]);
                    pma.normalize = false;
                    futures.add(pma.fork());
                }
                PointMultAddTask task = new PointMultAddTask(values[0], values[1]);
                task.normalize = false;
                ECPoint result = task.compute();
                for(ForkJoinTask<ECPoint> future : futures){
                    result = result.add(future.join());
                }
                if(normalize){
                    result = result.normalize();
                }
                return result;
            }
        }
    }

    public static class PowMultTask extends RecursiveTask<BigInteger> {

        final Object[] values;

        public PowMultTask(Object... values) {
            this.values = values;
        }

        @Override
        protected BigInteger compute() {
            if(values.length == 3){
                long msStart = System.currentTimeMillis();
                final BigInteger a = (BigInteger) values[0];
                final BigInteger b = (BigInteger) values[1];
                final BigInteger q = (BigInteger) values[2];
                BigInteger result = a.modPow(b,q);
                return result;
            }else{
                List<ForkJoinTask<BigInteger>> futures = new ArrayList<>();
                BigInteger q = (BigInteger) values[values.length - 1];
                long msStart = System.currentTimeMillis();
                for(int i = 2; i < values.length - 1; i += 2){
                    PowMultTask pma = new PowMultTask(values[i], values[i+1], q);
                    futures.add(pma.fork());
                }
                PowMultTask task = new PowMultTask(values[0], values[1], q);
                BigInteger result = task.compute();
                for(ForkJoinTask<BigInteger> future : futures){
                    result = result.multiply(future.join()).mod(q);
                }
                return result;
            }
        }
    }
}
