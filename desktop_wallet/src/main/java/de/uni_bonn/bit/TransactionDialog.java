package de.uni_bonn.bit;

import ca.odell.glazedlists.BasicEventList;
import ca.odell.glazedlists.EventList;
import ca.odell.glazedlists.swing.GlazedListsSwing;
import org.bitcoinj.core.*;
import org.bitcoinj.params.RegTestParams;
import com.google.zxing.WriterException;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import de.uni_bonn.bit.wallet_protocol.IWalletProtocol;

import javax.swing.*;
import javax.swing.text.DefaultFormatterFactory;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.DecimalFormat;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * This dialog is used to create a new transaction and to sign it with two-party signature protocol. In this dialog, the
 * user enters the target address and the amount of Bitcoins to send. After the transaction has been created, the dialog
 * displays a QR code which can be scanned with the phone wallet to start the two-party signature protocol.
 */
public class TransactionDialog extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JTextField addressTextField;
    private JButton generateTransactionButton;
    private JTextPane infoTextPane;
    private JLabel qrCodeLabel;
    private JFormattedTextField amountTextField;
    private JTable tblOutputs;
    private JScrollPane tblOutputsPane;

    private Wallet wallet;
    private TransactionBroadcaster broadcaster;
    private ProtocolServer server;

    public TransactionDialog(Wallet wallet, TransactionBroadcaster broadcaster) {
        setContentPane(contentPane);
        setModal(true);
        infoTextPane.setBackground(contentPane.getBackground());
        tblOutputsPane.setVisible(false);
        setTitle("Send Bitcoins");
        pack();
        this.wallet = wallet;
        this.broadcaster = broadcaster;
        amountTextField.setValue(new Double(0));
        amountTextField.setFormatterFactory(new DefaultFormatterFactory(new NumberFormatter(new DecimalFormat("0.00"))));
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                onClose();
            }
        });
        generateTransactionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                generateTransactionButton_Clicked(e);
            }
        });
        buttonOK.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onClose();
            }
        });
    }

    private void onClose() {
        if (server != null) {
            server.close();
        }
        dispose();
    }


    public void generateTransactionButton_Clicked(ActionEvent e) {
        try {
            //Close the old server, so the port is free again
            if (server != null) {
                server.close();
            }
            KeyShareWalletExtension walletEx = ((KeyShareWalletExtension) wallet.addOrGetExistingExtension(new KeyShareWalletExtension()));

            Address receiverAddress = new Address(TransactionHelper.netParams, addressTextField.getText());
            Double amountDouble = (Double) amountTextField.getValue();
            Coin amount = Coin.valueOf(Math.round(amountDouble * 100000000));
            Wallet.SendRequest sendRequest = Wallet.SendRequest.to(receiverAddress, amount);
            sendRequest.changeAddress = walletEx.getAddress();
            sendRequest.missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;
            wallet.completeTx(sendRequest);

            tblOutputs.setModel(GlazedListsSwing.eventTableModel(createOutputsList(sendRequest.tx),
                    new String[]{"address", "amount"},
                    new String[]{"Address", "BTC"},
                    new boolean[]{false, false}));
            //hack to ensure correct column sizes. Real columns sizes are proportions of the preferred width.
            tblOutputs.getColumnModel().getColumn(0).setPreferredWidth(800);
            tblOutputs.getColumnModel().getColumn(1).setPreferredWidth(200);
            tblOutputsPane.setVisible(true);

            List<String> ipAddresses = IPAddressHelper.getAllUsableIPAddresses();

            WalletProtocolImpl walletProtocolImpl = new WalletProtocolImpl(sendRequest.tx, new MyWalletProtocolListener(),
                    walletEx.getPrivateKey(), walletEx.getOtherPublicKey(), walletEx.getPkpDesktop(),
                    walletEx.getPkpPhone(), walletEx.getDesktopBCParameters(), walletEx.getPhoneBCParameters());
            server = new ProtocolServer(IWalletProtocol.class, walletProtocolImpl);
            qrCodeLabel.setIcon(new ImageIcon(QRCodeHelper.CreateQRCodeForTLSSetup(
                    ipAddresses, server.getPublicKey()
            )));
        } catch (WriterException we) {
            qrCodeLabel.setIcon(null);
            infoTextPane.setText("Exception while creating the QR code:\n" + we.getMessage());
        } catch (AddressFormatException afe) {
            qrCodeLabel.setIcon(null);
            infoTextPane.setText("The receiver address is incorrect:\n" + afe.getMessage());
        } catch (IllegalArgumentException iae) {
            qrCodeLabel.setIcon(null);
            infoTextPane.setText("Something went wrong when creating the transaction:\n" + iae.getMessage());
        } catch (InsufficientMoneyException ime) {
            qrCodeLabel.setIcon(null);
            infoTextPane.setText("Insufficient funds to complete this transaction:\n" + ime.getMessage());
        } catch (UnknownHostException e1) {
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (InvalidKeySpecException e1) {
            e1.printStackTrace();
        }
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        contentPane = new JPanel();
        contentPane.setLayout(new GridLayoutManager(7, 1, new Insets(10, 10, 10, 10), -1, -1));
        contentPane.setMinimumSize(new Dimension(400, 450));
        contentPane.setPreferredSize(new Dimension(400, 450));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel1, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel1.add(spacer1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        buttonOK = new JButton();
        buttonOK.setActionCommand("");
        buttonOK.setText("Close");
        panel2.add(buttonOK, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Address:");
        panel3.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addressTextField = new JTextField();
        addressTextField.setText("myaxzyLuJjfivCSrCwWEDaAMiyk7XkXXoX");
        panel3.add(addressTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Amount:");
        panel3.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        amountTextField = new JFormattedTextField();
        amountTextField.setText("");
        panel3.add(amountTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        generateTransactionButton = new JButton();
        generateTransactionButton.setText("Generate Transaction");
        panel4.add(generateTransactionButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel4.add(spacer2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel5, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, new Dimension(-1, 200), null, null, 0, false));
        qrCodeLabel = new JLabel();
        qrCodeLabel.setText("");
        panel5.add(qrCodeLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        contentPane.add(spacer3, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        infoTextPane = new JTextPane();
        infoTextPane.setEditable(false);
        infoTextPane.setText("Please enter receiver address and amount and click on Generate Transaction");
        contentPane.add(infoTextPane, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_NORTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 30), null, 0, false));
        tblOutputsPane = new JScrollPane();
        tblOutputsPane.setVisible(true);
        contentPane.add(tblOutputsPane, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(-1, 70), null, 0, false));
        tblOutputs = new JTable();
        tblOutputs.setVisible(true);
        tblOutputsPane.setViewportView(tblOutputs);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return contentPane;
    }

    private class MyWalletProtocolListener implements WalletProtocolImpl.WalletProtocolListener {

        @Override
        public void protocolCompleted(final Transaction transaction) {
            Logger.getLogger(TransactionDialog.class).info("Final Transaction stats: #inputs=" + transaction.getInputs().size() + " size=" + transaction.bitcoinSerialize().length);
            broadcaster.broadcastTransaction(transaction);
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    infoTextPane.setText("Transaction signing protocol successfully completed.");
                }
            });
        }

        @Override
        public void protocolFailed(Exception exception) {

        }
    }

    public static class AddressAmountPair {
        private String address, amount;

        public AddressAmountPair(String address, String amount) {
            this.address = address;
            this.amount = amount;
        }

        public String getAddress() {
            return address;
        }

        public String getAmount() {
            return amount;
        }
    }

    private EventList<AddressAmountPair> createOutputsList(Transaction transaction) {
        KeyShareWalletExtension walletExtension = (KeyShareWalletExtension) wallet.addOrGetExistingExtension(new KeyShareWalletExtension());
        EventList<AddressAmountPair> result = new BasicEventList<>();
        for (TransactionOutput transactionOutput : transaction.getOutputs()) {
            String addressString = transactionOutput.getScriptPubKey().getToAddress(RegTestParams.get()).toString();
            if (addressString.equals(walletExtension.getAddressAsString())) {
                addressString = "Change ("
                        + addressString.substring(0, 4)
                        + "..."
                        + addressString.substring(addressString.length() - 4, addressString.length())
                        + ")";
            }
            result.add(new AddressAmountPair(addressString,
                    transactionOutput.getValue().toFriendlyString())
            );
        }
        result.add(new AddressAmountPair("Miner fee",
                TransactionHelper.computeOverpay(transaction).toFriendlyString()));
        return result;
    }

}
