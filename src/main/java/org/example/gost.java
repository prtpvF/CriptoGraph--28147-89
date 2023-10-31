package org.example;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Scanner;

public class gost {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Генерируем случайный ключ
        byte[] key = generateRandomKey();
        System.out.println("Введите строку");
        Scanner scanner = new Scanner(System.in);

        String message = scanner.nextLine();
        byte[] plaintext = message.getBytes("UTF-8");

        // Зашифрование
        byte[] ciphertext = encrypt(plaintext, key);
        System.out.println("Зашифрованное сообщение: " + Base64.getEncoder().encodeToString(ciphertext));

        // Расшифрование
        byte[] decryptedText = decrypt(ciphertext, key);
        System.out.println("Расшифрованное сообщение: " + new String(decryptedText, "UTF-8"));
    }

    public static byte[] generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32]; // 256 бит
        random.nextBytes(key);
        return key;
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        BlockCipher engine = new GOST28147Engine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(engine, 64));
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), new byte[8]));

        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
        int len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        cipher.doFinal(ciphertext, len);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        BlockCipher engine = new GOST28147Engine();
        BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(engine, 64));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), new byte[8]));

        byte[] decryptedText = new byte[cipher.getOutputSize(ciphertext.length)];
        int len = cipher.processBytes(ciphertext, 0, ciphertext.length, decryptedText, 0);
        cipher.doFinal(decryptedText, len);
        return decryptedText;
    }
}