package de.uni_bonn.bit;

import de.uni_bonn.bit.wallet_protocol.IPairingProtocol;
import de.uni_bonn.bit.wallet_protocol.IWalletProtocol;
import de.uni_bonn.bit.wallet_protocol.PairingMessage;
import de.uni_bonn.bit.wallet_protocol.ZKProofInit;
import org.apache.avro.ipc.NettyServer;
import org.apache.avro.ipc.NettyTransceiver;
import org.apache.avro.ipc.reflect.ReflectRequestor;
import org.apache.avro.ipc.reflect.ReflectResponder;
import org.bitcoinj.core.ECKey;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;

import static de.uni_bonn.bit.BitcoinECMathHelper.convertPointToPubKEy;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPrivKeyToBigInt;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertPubKeyToPoint;
import static de.uni_bonn.bit.BitcoinECMathHelper.convertBigIntToPrivKey;

/**
 * Created by chris on 17.11.14.
 */
public class PairingSerializationTest {

    @Test
    public void testThePairingProtocol() throws IOException {
        PaillierKeyPair myKeyPair = PaillierKeyPair.generatePaillierKeyPair();
        BCParameters myBCParameters = BCParameters.generateBCParameters();
        ECKey myECKey = convertBigIntToPrivKey(new BigInteger("2"));

        PairingProtocolTestImpl impl = new PairingProtocolTestImpl();
        NettyServer server = new NettyServer(new ReflectResponder(IPairingProtocol.class,
                impl), new InetSocketAddress(20000));

        NettyTransceiver transceiver = new NettyTransceiver(new InetSocketAddress(20000));
        IPairingProtocol proxy = ReflectRequestor.getClient(IPairingProtocol.class, transceiver);

        ZKProofInit myZKProof = ZKProofInit.generate(myBCParameters, "Desktop init");
        PairingMessage msg = new PairingMessage(convertPubKeyToPoint(myECKey),
                myKeyPair.clearPrivateKey(), myBCParameters.clearPrivate(), myZKProof);
        PairingMessage answer = proxy.pair(msg);
        answer.getZkProofInit().verify(answer.getBcParameters(), "Phone init");
        server.close();
    }


    public static class PairingProtocolTestImpl implements IPairingProtocol{

        PaillierKeyPair myKeyPair;
        BCParameters myBCParameters;
        ECKey myECKey;

        public PairingProtocolTestImpl(){
            myKeyPair = PaillierKeyPair.generatePaillierKeyPair();
            myBCParameters = BCParameters.generateBCParameters();
            myECKey = convertBigIntToPrivKey(new BigInteger("2"));
        }

        @Override
        public PairingMessage pair(PairingMessage pairingMessage) {
            pairingMessage.getZkProofInit().verify(pairingMessage.getBcParameters(), "Desktop init");
            ZKProofInit myZKProof = ZKProofInit.generate(myBCParameters, "Phone init");
            PairingMessage answer = new PairingMessage(convertPubKeyToPoint(myECKey), myKeyPair.clearPrivateKey(),
                    myBCParameters.clearPrivate(), myZKProof);
            return answer;
        }
    }
}
