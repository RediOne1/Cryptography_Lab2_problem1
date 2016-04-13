package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.KeyStore;
import java.util.Random;
import java.util.Scanner;

public class Main {

    private static byte[] iv = new byte[]{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    private static String file1 = "test";
    private static String file2 = "test2";
    private static String inputFileName;

    public static void main(String[] args) {
        if (args.length != 3)
            return;

        String encryptionMode = args[0];
        String keystorePath = args[1];
        String keyAlias = args[2];

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password to the keystore: ");
        String password = scanner.nextLine();

        SecretKey secretKey;
        File file = new File(keystorePath);
        if (!file.exists())
            createNewKeystore(file, password.toCharArray(), keyAlias);

        secretKey = getSecretKey(file, password.toCharArray(), keyAlias);

        if(file2 == null)
            inputFileName = file1;
        else {
            inputFileName = new Random().nextBoolean() ? file1 : file2;
        }

        encryption(encryptionMode, secretKey);
        decryption(encryptionMode, secretKey);

    }

    //region Create keystore
    private static void createNewKeystore(File file, char[] password, String keyAlias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), password);

            // generate a secret key for AES encryption
            SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
            KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
            keyStore.setEntry(keyAlias, keyStoreEntry, keyPassword);
            keyStore.store(new FileOutputStream(file), password);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //endregion

    //region get secret key from Keystore
    private static SecretKey getSecretKey(File file, char[] password, String keyAlias) {
        SecretKey key = null;
        try {
            InputStream fis = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(fis, password);

            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);

            KeyStore.Entry entry = keyStore.getEntry(keyAlias, keyPassword);
            key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();


        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }
    //endregion

    //region encryption
    private static void encryption(String encryptionMode, SecretKey secretKey) {
        try {

            FileInputStream fileInputStream = new FileInputStream(new File(inputFileName));
            BufferedInputStream reader = new BufferedInputStream(fileInputStream);
            byte[] buffer = new byte[1024];

            FileOutputStream fos = new FileOutputStream(new File("encrypted_" + inputFileName));

            Cipher cipher = Cipher.getInstance(encryptionMode);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            while (reader.read(buffer) > 0) {
                byte[] bytes = cipher.update(buffer);
                fos.write(bytes);
            }

            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //endregion

    //region decryption
    private static void decryption(String encryptionMode, SecretKey secretKey) {
        try {
            FileInputStream fileInputStream = new FileInputStream(new File("encrypted_" + inputFileName));
            BufferedInputStream reader = new BufferedInputStream(fileInputStream);
            byte[] buffer = new byte[1024];

            FileOutputStream fos = new FileOutputStream(new File("decrypted_" + inputFileName));

            Cipher cipher = Cipher.getInstance(encryptionMode);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            while (reader.read(buffer) > 0) {
                byte[] bytes = cipher.update(buffer);
                fos.write(bytes);
            }
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //endregion
}
