import RSA.RSAEncryptor;
import RSA.RSAKeyGen;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidKeyException;

public class Window extends JFrame {
    private final JButton code, decode, generate;
    private final JTextField strField, publicKeyField, privateKeyField, resField;
    private final JLabel strLabel, publicKeyLabel, privateKeyLabel, resLabel;

    public Window() {
        super("Lab 3");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLocation(100, 100);
        setSize(1000, 900);

        JPanel grid = new JPanel();
        GridLayout layout = new GridLayout(0, 3, 12, 12);
        grid.setLayout(layout);

        code = new JButton("Закодировать");
        decode = new JButton("Декодировать");
        generate = new JButton("Сгенерировать ключи");

        strField = new JTextField("Мама мыла раму", 10);
        publicKeyField = new JTextField(10);
        privateKeyField = new JTextField(10);

        strLabel = new JLabel("Сообщение");
        publicKeyLabel = new JLabel("Публичный ключ");
        privateKeyLabel = new JLabel("Приватный ключ");

        resLabel = new JLabel("Результат");
        resField = new JTextField();

        grid.add(strLabel);
        grid.add(strField);
        grid.add(generate);

        grid.add(publicKeyLabel);
        grid.add(publicKeyField);
        grid.add(code);

        grid.add(privateKeyLabel);
        grid.add(privateKeyField);
        grid.add(decode);

        grid.add(resLabel);
        grid.add(resField);

        getContentPane().add(grid);

        aHandler handler = new aHandler();
        code.addActionListener(handler);
        decode.addActionListener(handler);
        generate.addActionListener(handler);

        setVisible(true);
    }

    public class aHandler implements ActionListener {
        RSAKeyGen keyGen = RSAKeyGen.getInstance();
        RSAEncryptor encryptor = RSAEncryptor.getInstance();
        String msg = null;
        String privateKey = null;
        String publicKey = null;

        @Override
        public void actionPerformed(ActionEvent e) {
            msg = strField.getText();
            privateKey = privateKeyField.getText();
            publicKey = publicKeyField.getText();

            try {
                if (generate.equals(e.getSource())) {
                    keyGen.generateNewKeys();
                    privateKeyField.setText(keyGen.getPrivateKey());
                    publicKeyField.setText(keyGen.getPublicKey());
                }
                else if (code.equals(e.getSource())) {
                    encryptor.registerKeys(privateKey, publicKey);
                    resField.setText(encryptor.code(msg));
                }
                else if (decode.equals(e.getSource())) {
                    encryptor.registerKeys(privateKey, publicKey);
                    resField.setText(encryptor.decode(msg));
                }
                else {
                    throw new IOException("Произошла неизвестная ошибка");
                }
            }
            catch (IOException ex) {
                JOptionPane.showMessageDialog(null, ex.getMessage());
            }
            catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                JOptionPane.showMessageDialog(null, "Неправильный ключ");
            }
        }
    }
}
