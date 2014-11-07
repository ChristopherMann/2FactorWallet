package de.uni_bonn.bit;

import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.testing.TestWithWallet;
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.*;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertPointToPubKEy;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPrivKeyToBigInt;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPubKeyToPoint;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * This is the base class for the transaction signer tests. It uses the
 * {@link org.bitcoinj.testing.TestWithWallet} class from bitcoinj to setup test transactions. Additionally,
 * it performs the setup for several parameters.
 */
@RunWith(Parameterized.class)
public class TransactionSignerBaseTest extends TestWithWallet {
    @Parameterized.Parameters
    public static Collection<ECKey[]> data(){
        BigInteger nEC = ECKey.CURVE.getN();
        return Lists.newArrayList(
                new ECKey[]{
                        convertBigIntToPrivKey(new BigInteger("1")), convertBigIntToPrivKey(new BigInteger("2"))
                },
                new ECKey[]{
                        convertBigIntToPrivKey(nEC.subtract(new BigInteger("1"))), convertBigIntToPrivKey(nEC.subtract(new BigInteger("2")))
                });
    }

    @Parameterized.Parameter(0)
    public ECKey desktopKeyShare;
    @Parameterized.Parameter(1)
    public ECKey phoneKeyShare;

    public ECKey commonPublicKey;

    public BCParameters desktopBCParameters;
    public BCParameters phoneBCParameters;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        //setup key material
        commonPublicKey = convertPointToPubKEy(
                convertPubKeyToPoint(desktopKeyShare).multiply(convertPrivKeyToBigInt(phoneKeyShare)));

        //add money to the common addresses and common keys to wallet
        for(int i= 0; i < 3; i++){
            ECKey key = commonPublicKey;
            wallet.addKey(key);
            sendMoneyToWallet(this.wallet, Coin.valueOf(0,1), key.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        }

        desktopBCParameters = BCParameters.generateBCParameters();
        phoneBCParameters = BCParameters.generateBCParameters2();
    }

    @Test
    public void test(){
        System.out.println("Execution");
        System.out.println(desktopKeyShare.toString());
        System.out.println(phoneKeyShare.toString());
        System.out.println("");
    }

    public static ECKey clearedCopy(ECKey key){
        ECKey result = convertPointToPubKEy(convertPubKeyToPoint(key));
        return result;
    }
}
