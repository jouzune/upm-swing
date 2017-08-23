package com._17od.upm.gui;

import com._17od.upm.util.Translator;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EtchedBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class NewDatabaseFromUrlDialog extends EscapeDialog {
    private static final long serialVersionUID = 1L;

    public JTextField urlTextField;
    public JTextField usernameTextField;
    public JPasswordField passwordTextField;
    public JPasswordField confirmPasswordTextField;
    private boolean okClicked = false;

    public NewDatabaseFromUrlDialog(final JFrame frame) {
        super(frame, "New Database From URL", true);

        Container container = getContentPane();

        // Create a pane with an empty border for spacing
        Border emptyBorder = BorderFactory.createEmptyBorder(2, 5, 5, 5);
        JPanel emptyBorderPanel = new JPanel();
        emptyBorderPanel.setLayout(new BoxLayout(emptyBorderPanel, BoxLayout.Y_AXIS));
        emptyBorderPanel.setBorder(emptyBorder);
        container.add(emptyBorderPanel);

        // Create a pane with an title etched border
        Border etchedBorder = BorderFactory.createEtchedBorder(EtchedBorder.LOWERED);
        Border etchedTitleBorder = BorderFactory.createTitledBorder(etchedBorder, ' ' + Translator.translate("remoteLocation") + ' ');
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(etchedTitleBorder);
        emptyBorderPanel.add(mainPanel);

        GridBagConstraints c = new GridBagConstraints();

        // The URL Label row
        JLabel urlLabel = new JLabel(Translator.translate("url"));
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(0, 5, 0, 0);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(urlLabel, c);

        // The Remote URL input field row
        urlTextField = new JTextField(20);
        c.gridx = 0;
        c.gridy = 1;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(0, 5, 5, 5);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(urlTextField, c);

        // The username label field
        JLabel usernameLabel = new JLabel("Input a username");
        c.gridx = 0;
        c.gridy = 2;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(5, 5, 0, 0);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(usernameLabel, c);

        // The username input field
        usernameTextField = new JTextField(10);
        c.gridx = 0;
        c.gridy = 3;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(0, 5, 5, 5);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.NONE;
        mainPanel.add(usernameTextField, c);

        // The password label field
        JLabel passwordLabel = new JLabel("Input a password");
        c.gridx = 0;
        c.gridy = 4;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(5, 5, 0, 0);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(passwordLabel, c);

        // The password input field
        passwordTextField = new JPasswordField(10);
        c.gridx = 0;
        c.gridy = 5;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(0, 5, 5, 5);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.NONE;
        mainPanel.add(passwordTextField, c);

        // The confirm password label field
        JLabel confirmPasswordLabel = new JLabel("Input the password again");
        c.gridx = 0;
        c.gridy = 6;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(5, 5, 0, 0);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(confirmPasswordLabel, c);

        // The confirm password input field
        confirmPasswordTextField = new JPasswordField(10);
        c.gridx = 0;
        c.gridy = 7;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = new Insets(0, 5, 5, 5);
        c.weightx = 1;
        c.weighty = 0;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.NONE;
        mainPanel.add(confirmPasswordTextField, c);

        // Some spacing
        Component verticalSpace = Box.createVerticalGlue();
        c.gridy = 6;
        c.weighty = 1;
        mainPanel.add(verticalSpace, c);

        // The buttons row
        JPanel buttonPanel = new JPanel(new FlowLayout());

        JButton okButton = new JButton(Translator.translate("ok"));
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                okClicked = true;
                setVisible(false);
                dispose();
            }
        });
        buttonPanel.add(okButton);

        JButton cancelButton = new JButton(Translator.translate("cancel"));
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                setVisible(false);
                dispose();
            }
        });
        buttonPanel.add(cancelButton);

        emptyBorderPanel.add(buttonPanel);

    }


    public JTextField getPasswordTextField() {
        return passwordTextField;
    }


    public JTextField getConfirmPasswordTextField() {
        return confirmPasswordTextField;
    }


    public JTextField getUrlTextField() {
        return urlTextField;
    }


    public JTextField getUsernameTextField() {
        return usernameTextField;
    }


    public boolean getOkClicked() {
        return okClicked;
    }
}
