package de.uni_bonn.bit.wallet_protocol;

/**
 * This interface defines the pairing protocol.
 */
public interface IPairingProtocol {

    public PairingMessage pair(PairingMessage pairingMessage);
}
