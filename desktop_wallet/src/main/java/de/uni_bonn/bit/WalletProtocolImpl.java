package de.uni_bonn.bit;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import de.uni_bonn.bit.wallet_protocol.*;

import java.util.ArrayList;
import java.util.List;

/**
 * This class implements the {@link de.uni_bonn.bit.wallet_protocol.IWalletProtocol}. It contains the desktop's logic
 * for the signature protocol. This class is used to create an avro server.
 */
public class WalletProtocolImpl implements IWalletProtocol {

    private Transaction transaction;
    private DesktopTransactionSigner signer;
    private WalletProtocolListener listener;

    public WalletProtocolImpl(Transaction transaction, WalletProtocolListener listener, ECKey privateKey, ECKey otherPublicKey,
                              PaillierKeyPair pkpDesktop, PaillierKeyPair pkpPhone, BCParameters desktopBCParameters,
                              BCParameters phoneBCParameters
    ){
        this.transaction = transaction;
        this.listener = listener;
        this.signer = new DesktopTransactionSigner(transaction, privateKey, otherPublicKey, pkpDesktop, pkpPhone,
                desktopBCParameters, phoneBCParameters);
    }

    @Override
    public TransactionInfo fetchTransactionInfo() {
        List<Transaction> connectedTransactions = new ArrayList<>();
        for(TransactionInput input : transaction.getInputs()){
            connectedTransactions.add(input.getConnectedOutput().getParentTransaction());
        }
        return new TransactionInfo(transaction);
    }

    @Override
    public SignatureParts[] getSignatureParts() {
        return signer.computeSignatureParts();
    }

    @Override
    public EphemeralPublicValueWithProof[] getEphemeralPublicValuesWithProof(EphemeralValueShare[] ephemeralValueShares) {
        return signer.computeEphemeralPublicValue(ephemeralValueShares);
    }

    @Override
    public boolean sendEncryptedSignatures(EncryptedSignatureWithProof[] encryptedSignatures) {
        transaction = signer.addEncryptedSignaturesToTransaction(encryptedSignatures);
        listener.protocolCompleted(transaction);
        return true;
    }

    public static interface WalletProtocolListener{
        public void protocolCompleted(final Transaction transaction);
        public void protocolFailed(final Exception exception);
    }
}
