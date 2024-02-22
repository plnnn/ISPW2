package lt.viko.eif.nychyporuk.ispw2;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class EncryptDecryptSystem {
    private static final String OUTPUT_FOLDER = "output/";
    private static final String INPUT_FOLDER = "input/";

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            System.out.print("Encrypt/Decrypt: ");
            String operation = reader.readLine();

            if (operation.equals("Encrypt")) {
                System.out.print("Enter plaintext: ");
                String plaintext = reader.readLine();

                System.out.print("Enter secret key: ");
                String key = reader.readLine();

                System.out.print("Choose encryption mode (ECB, CBC, CFB): ");
                String modeStr = reader.readLine();
                CipherMode mode = CipherMode.valueOf(modeStr.toUpperCase());

                System.out.print("Enter output file name (without extension): ");
                String outputFile = reader.readLine();

                String cipherText = encrypt(plaintext, key, mode);
                saveToFile(OUTPUT_FOLDER + outputFile + "_cipher.txt", cipherText);

                String decryptedText = decrypt(OUTPUT_FOLDER + outputFile + "_cipher.txt", key, mode);
                saveToFile(OUTPUT_FOLDER + outputFile + "_decrypted.txt", decryptedText);

                System.out.println("Encryption and decryption completed.");
            }
            else if (operation.equals("Decrypt"))
            {
                System.out.print("Enter secret key: ");
                String key = reader.readLine();

                System.out.print("Choose decryption mode (ECB, CBC, CFB): ");
                String modeStr = reader.readLine();
                CipherMode mode = CipherMode.valueOf(modeStr.toUpperCase());

                System.out.print("Read cipher from Input/File: ");
                String readModeStr = reader.readLine();

                if (readModeStr.equals("File"))
                {
                    System.out.print("Enter input file name (without extension): ");
                    String inputFile = reader.readLine();

                    System.out.print("Enter output file name (without extension): ");
                    String outputFile = reader.readLine();

                    String decryptedText = decrypt(INPUT_FOLDER + inputFile + ".txt", key, mode);
                    saveToFile(OUTPUT_FOLDER + outputFile + "_decrypted.txt", decryptedText);

                    System.out.println("Encryption and decryption completed.");
                }
                else if (readModeStr.equals("Input"))
                {
                    System.out.print("Enter cipher: ");
                    String cipher = reader.readLine();

                    System.out.print("Enter output file name (without extension): ");
                    String outputFile = reader.readLine();

                    saveToFile(INPUT_FOLDER + outputFile + "_cipher_given.txt", cipher);
                    String decryptedText = decrypt(INPUT_FOLDER + outputFile + "_cipher_given.txt" + ".txt", key, mode);
                    saveToFile(OUTPUT_FOLDER + outputFile + "_decrypted.txt", decryptedText);

                    System.out.println("Encryption and decryption completed.");
                }
                else
                {
                    System.out.println("There is no such source of cipher.");
                }
            }
            else
            {
                System.out.println("There is no such operation.");
            }
        }
        catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String plaintext, String key, CipherMode mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {

        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode.name() + "/PKCS5Padding");

        if (mode != CipherMode.ECB) {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

            byte[] encryptedDataWithIv = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, encryptedDataWithIv, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, encryptedDataWithIv, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(encryptedDataWithIv);
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
    }

    private static String decrypt(String cipherFile, String key, CipherMode mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, IOException {

        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode.name() + "/PKCS5Padding");

        String cipherText = readFromFile(cipherFile);

        if (mode != CipherMode.ECB) {
            byte[] encryptedDataWithIv = Base64.getDecoder().decode(cipherText);
            byte[] iv = new byte[cipher.getBlockSize()];
            System.arraycopy(encryptedDataWithIv, 0, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            byte[] encryptedBytes = new byte[encryptedDataWithIv.length - iv.length];
            System.arraycopy(encryptedDataWithIv, iv.length, encryptedBytes, 0, encryptedBytes.length);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes);
        }
        else {
            byte[] encryptedBytes = Base64.getDecoder().decode(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes);
        }
    }

    private static void saveToFile(String fileName, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            writer.write(content);
        }
    }

    private static String readFromFile(String fileName) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }

            return content.toString();
        }
    }

    private enum CipherMode {
        ECB,
        CBC,
        CFB
    }
}

/*

AES
Block cipher
key 128/192/256 bits
rounds 10/12/14
blocks 128 bits

Encryption
1. SubBytes
2. ShiftRows
3. MixColumns
4. AddRoundKeys

Decryption
1. AddRoundKeys
2. Inverse MixColumns
3. ShiftRows
4. Inverse SubBytes

Mode

 */