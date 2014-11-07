package de.uni_bonn.bit;

import org.bitcoinj.core.ECKey;
import de.uni_bonn.bit.wallet_protocol.IPairingProtocol;
import de.uni_bonn.bit.wallet_protocol.PairingMessage;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;

/**
 * This class implements the {@link de.uni_bonn.bit.wallet_protocol.IPairingProtocol}. It contains the desktop's logic
 * for the pairing protocol. This class is used to create an avro server.
 */
public class PairingProtocolImpl implements IPairingProtocol{

    private BigInteger keyShare;
    private String address;
    private PairingProtocolListener listener;
    private KeyShareWalletExtension walletExtension;

    private static final BigInteger nEC = ECKey.CURVE.getN();

    public PairingProtocolImpl(PairingProtocolListener listener, KeyShareWalletExtension walletExtension) {
        this.listener = listener;
        this.keyShare = IntegerFunctions.randomize(nEC);
        this.walletExtension = walletExtension;
    }

    @Override
    public PairingMessage pair(PairingMessage message) {
        ECPoint publicKey = ECKey.CURVE.getG().multiply(keyShare).normalize();
        PaillierKeyPair pkp = PaillierKeyPair.generatePaillierKeyPair();
        BCParameters desktopBCParameters = BCParameters.generateBCParameters();
        PairingMessage response = new PairingMessage(publicKey, pkp, desktopBCParameters);
        walletExtension.setPrivateKey(BitcoinECMathHelper.convertBigIntToPrivKey(keyShare));
        walletExtension.setOtherPublicKey(BitcoinECMathHelper.convertPointToPubKEy(message.getOtherPublicKey()));
        walletExtension.setPkpDesktop(pkp);
        walletExtension.setPkpPhone(message.getPkp());
        walletExtension.setDesktopBCParameters(desktopBCParameters);
        walletExtension.setPhoneBCParameters(message.getBcParameters());
        listener.onProtocolCompleted();
        return response;
    }

    public static interface PairingProtocolListener{
        public void onProtocolCompleted();
        public void onProtocolException(Exception exception);
    }
}
