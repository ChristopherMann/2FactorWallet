package de.uni_bonn.bit.wallet_protocol;

/**
 * This interface defines the signature protocol executed by the desktop wallet and the phone wallet.
 */
public interface IWalletProtocol {

    public TransactionInfo fetchTransactionInfo();

    public SignatureParts[] getSignatureParts();

    public EphemeralPublicValueWithProof[] getEphemeralPublicValuesWithProof(EphemeralValueShare[] ephemeralValueShares);

    public boolean sendEncryptedSignatures(EncryptedSignatureWithProof[] encryptedSignatures);
}
