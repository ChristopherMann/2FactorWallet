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

import ca.odell.glazedlists.BasicEventList;
import ca.odell.glazedlists.gui.TableFormat;
import ca.odell.glazedlists.swing.AdvancedTableModel;
import ca.odell.glazedlists.swing.GlazedListsSwing;
import org.bitcoinj.core.*;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.store.*;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.WriterAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.bitcoinj.wallet.Protos;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static org.bitcoinj.core.Wallet.BalanceType;

/**
 * TThis class is the main window for the desktop part of the two-factor wallet. It displays the user's balance and a
 * list of the transactions. Most of the setup, include the pairing if the wallet has not been paired yet, is done
 * inside {@link de.uni_bonn.bit.MainWindow#startup()}
 */
public class MainWindow {
    JPanel panel1;
    private JLabel lblBalance;
    private JButton btnReceive;
    private JButton btnSend;
    private JTable tblTransactions;
    private JTextArea txtLog;

    private Wallet wallet;
    private BlockStore blockStore;
    private PeerGroup peerGroup;
    private final BasicEventList<Transaction> transactionList = new BasicEventList<>();

    private final Logger log = Logger.getLogger(MainWindow.class);

    public MainWindow() {
        //setup logger
        TextAreaAppender textAreaAppender = new TextAreaAppender();
        textAreaAppender.setThreshold(Level.INFO);
        textAreaAppender.setLayout(new PatternLayout("%d{HH:mm:ss,SS} %-5p: %m%n"));
        Logger.getRootLogger().addAppender(textAreaAppender);
    }

    /**
     * This method starts the desktop wallet. If the wallet has not yet been paired with a phone wallet, it will display
     * the pairing dialog. Afterwards, it loads the wallet file and the block store from disk and connects to the Bitcoin
     * network.
     */
    public void startup() {
        wallet = new Wallet(TransactionHelper.netParams);
        KeyShareWalletExtension walletExtension = new KeyShareWalletExtension();
        wallet.addExtension(walletExtension);
        File walletFile = new File("wallet.bin");
        if (!walletFile.exists()) {
            //No wallet found -> no pairing established yet -> open pairing dialog
            PairingDialog pairingDialog = new PairingDialog(walletExtension);
            pairingDialog.setVisible(true);
            if (pairingDialog.getResult() == PairingDialog.Result.FAIL) {
                System.exit(0);
            }
            //Compute common public key and add it to the wallet
            ECKey commonPublicKey = BitcoinECMathHelper.convertPointToPubKEy(
                    BitcoinECMathHelper.convertPubKeyToPoint(walletExtension.getOtherPublicKey())
                            .multiply(BitcoinECMathHelper.convertPrivKeyToBigInt(walletExtension.getPrivateKey())));

            commonPublicKey.setCreationTimeSeconds(Calendar.getInstance().getTimeInMillis() / 1000);
            wallet.importKey(commonPublicKey);
            try {
                wallet.saveToFile(walletFile);
            } catch (IOException e) {
                log.error("Wallet could not be saved to file after pairing.", e);
                throw new RuntimeException(e);
            }
        } else {
            try {
                FileInputStream walletStream = new FileInputStream(walletFile);
                Protos.Wallet walletProto = WalletProtobufSerializer.parseToProto(walletStream);
                wallet = new WalletProtobufSerializer().readWallet(TransactionHelper.netParams,
                        new WalletExtension[]{new KeyShareWalletExtension()}, walletProto);
            } catch (UnreadableWalletException e) {
                log.error("Wallet file could not be loaded.", e);
                throw new RuntimeException(e);
            } catch (FileNotFoundException e) {
                //Should never happen. We checked that the file exists.
                throw new RuntimeException(e);
            } catch (IOException e) {
                log.error("Wallet file could not be loaded.", e);
                throw new RuntimeException(e);
            }
        }
        wallet.autosaveToFile(walletFile, 1, TimeUnit.MINUTES, null);
        blockStore = null;
        try {
            blockStore = new SPVBlockStore(TransactionHelper.netParams, new File("blockstore.bin"));
            BlockChain chain = new BlockChain(TransactionHelper.netParams, wallet, blockStore);
            peerGroup = new PeerGroup(TransactionHelper.netParams, chain);
            peerGroup.addWallet(wallet);
            peerGroup.addAddress(new PeerAddress(InetAddress.getByName("127.0.0.1"), 9000));
            peerGroup.startAsync();
            peerGroup.startBlockChainDownload(null);
        } catch (BlockStoreException e) {
            log.error("Blockstore exception when creating a new block store.", e);
            throw new RuntimeException(e);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        initializeGui();
    }

    /**
     * This method correctly initializes the transaction table and the balance label.
     */
    private void initializeGui() {
        AdvancedTableModel<Transaction> transactionTableModel =
                GlazedListsSwing.eventTableModelWithThreadProxyList(transactionList, new TransactionTableFormat());
        tblTransactions.setModel(transactionTableModel);
        //hack to ensure correct column sizes. Real columns sizes are proportions of the preferred width.
        tblTransactions.getColumnModel().getColumn(0).setPreferredWidth(100);
        tblTransactions.getColumnModel().getColumn(1).setPreferredWidth(400);
        tblTransactions.getColumnModel().getColumn(2).setPreferredWidth(200);
        tblTransactions.getColumnModel().getColumn(3).setPreferredWidth(300);
        transactionList.addAll(wallet.getTransactions(false));
        lblBalance.setText(wallet.getBalance(BalanceType.AVAILABLE).toFriendlyString());

        btnSend.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new TransactionDialog(wallet, peerGroup).setVisible(true);
            }
        });
        btnReceive.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ReceivePaymentDialog(wallet.getImportedKeys().get(0).toAddress(RegTestParams.get()).toString()).setVisible(true);
            }
        });

        wallet.addEventListener(
                new AbstractWalletEventListener() {
                    @Override
                    public void onWalletChanged(final Wallet wallet) {
                        super.onWalletChanged(wallet);
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                lblBalance.setText(wallet.getBalance(BalanceType.AVAILABLE).toFriendlyString());
                            }
                        });
                    }

                    @Override
                    public void onCoinsReceived(Wallet wallet, final Transaction tx, Coin prevBalance, Coin newBalance) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                if (transactionList.isEmpty() || !transactionList.get(0).equals(tx)) {
                                    transactionList.add(0, tx);
                                }
                            }
                        });
                    }

                    @Override
                    public void onCoinsSent(Wallet wallet, final Transaction tx, Coin prevBalance, Coin newBalance) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                if (transactionList.isEmpty() || !transactionList.get(0).equals(tx)) {
                                    transactionList.add(0, tx);
                                }
                            }
                        });
                    }

                    @Override
                    public void onTransactionConfidenceChanged(Wallet wallet, final Transaction tx) {
                        super.onTransactionConfidenceChanged(wallet, tx);
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                //transactions are equal if their bitcoin serialization hash is equal. The hash stays the same
                                //when the confidence changes
                                int indexOfTx = transactionList.indexOf(tx);
                                transactionList.set(indexOfTx, tx);
                            }
                        });

                    }
                }
        );
    }

    public void onClose() {
        if (peerGroup != null) {
            peerGroup.stopAndWait();
        }
        if (wallet != null) {
            try {
                wallet.saveToFile(new File("wallet.bin.tmp"), new File("wallet.bin"));
            } catch (IOException e) {
                log.error("The wallet could not be saved!", e);
            }
        }
        if (blockStore != null) {
            try {
                blockStore.close();
            } catch (BlockStoreException e) {
                log.error("Exception while closing the block store.", e);
            }
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
        panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(2, 1, new Insets(5, 5, 5, 5), -1, -1));
        panel1.setMinimumSize(new Dimension(600, 500));
        panel1.setPreferredSize(new Dimension(600, 500));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 6, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("");
        panel2.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Balance:");
        panel2.add(label2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        lblBalance = new JLabel();
        lblBalance.setText("0 BTC");
        panel2.add(lblBalance, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel2.add(spacer1, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        btnSend = new JButton();
        btnSend.setText("Send");
        panel2.add(btnSend, new GridConstraints(0, 4, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnReceive = new JButton();
        btnReceive.setText("Receive");
        panel2.add(btnReceive, new GridConstraints(0, 5, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setDividerLocation(200);
        splitPane1.setDividerSize(5);
        splitPane1.setOrientation(0);
        panel3.add(splitPane1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane1);
        tblTransactions = new JTable();
        scrollPane1.setViewportView(tblTransactions);
        final JScrollPane scrollPane2 = new JScrollPane();
        splitPane1.setRightComponent(scrollPane2);
        txtLog = new JTextArea();
        scrollPane2.setViewportView(txtLog);
        final JLabel label3 = new JLabel();
        label3.setText("Transactions:");
        panel3.add(label3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel1;
    }

    public class TransactionTableFormat implements TableFormat<Transaction> {

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "In/Out";
                case 1:
                    return "Date";
                case 2:
                    return "Confidence";
                case 3:
                    return "Value";
            }
            return "";
        }

        @Override
        public Object getColumnValue(Transaction baseObject, int column) {
            switch (column) {
                case 0: // "In/Out"
                    long valueSent = baseObject.getValueSentFromMe(wallet).getValue();
                    long valueReceived = baseObject.getValueSentToMe(wallet).getValue();
                    if (valueSent == valueReceived) {
                        return "<-|>|";
                    } else if (valueSent > 0) {
                        return "<-|-|";
                    } else if (valueReceived > 0) {
                        return "--|>|";
                    } else {
                        return " ??? ";
                    }
                case 1:
                    return baseObject.getUpdateTime().toString();
                case 2: //Confirmation
                    if (baseObject.hasConfidence()) {
                        if (baseObject.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING) {
                            return "  ✔  ";
                        } else if (baseObject.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.PENDING) {
                            return " ... ";
                        }
                        return "???";
                    }
                case 3: // Value
                    return baseObject.getValue(wallet).toFriendlyString();
            }
            return "";
        }
    }

    public class TextAreaAppender extends WriterAppender {
        @Override
        public void append(LoggingEvent event) {
            final String messageString = this.layout.format(event);
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    txtLog.append(messageString);
                }
            });
        }
    }
}
