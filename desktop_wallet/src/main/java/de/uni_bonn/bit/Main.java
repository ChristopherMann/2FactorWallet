package de.uni_bonn.bit;

import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.store.BlockStoreException;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.UnknownHostException;

/**
 * This class just contains the startup code, which sets up the logging and creates the main window.
 */
public class Main {

    public static void main(String[] args) throws BlockStoreException, UnknownHostException, InsufficientMoneyException {
        ConsoleAppender appender = new ConsoleAppender(
                new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN), ConsoleAppender.SYSTEM_OUT);
        appender.setThreshold(Level.INFO);
        Logger.getRootLogger().addAppender(appender);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                final JFrame frame = new JFrame("MainWindow");
                final MainWindow mainWindow = new MainWindow();
                frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
                frame.addWindowListener(new WindowAdapter() {
                    @Override
                    public void windowClosing(WindowEvent e) {
                        mainWindow.onClose();
                        frame.dispose();
                    }
                });
                frame.setContentPane(mainWindow.panel1);
                frame.pack();
                //frame.setIconImage(Toolkit.getDefaultToolkit().getImage(getClass().getResource("/de/uni_bonn/bit/wallet_logo.png")));
                frame.setTitle("2Factor Wallet");
                frame.setVisible(true);
                mainWindow.startup();
            }
        });
    }

}
