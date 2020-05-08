import org.jasypt.util.text.AES256TextEncryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class App {
    public static void main(String[] args) {

        var key = "JDHQINFAFB12JSKDFOWOW023@3432FKDSF";
        var key16 = "JDHQINFAFB12JSKD";
        var iv = "1234567890123456";
        var input = "EBjr2XRWtQu9Oag_IMq1Kv1EcPw.*AAJTSQACMDIAAlNLABx4TEZlWC9Iams0ZUZIWlNlSGxkSTM1VitwY0E9AAJTMQACMDU.*";
        var output = encrypt(input, key);
        System.out.println("Encrypted: " + output);
        output = decrypt(output, key);
        System.out.println("Decrypted: " + output);

        output = encrypt2(input, key16, iv);
        System.out.println("Encrypted: " + output);
        output = decrypt2(output, key16, iv);
        System.out.println("Decrypted: " + output);

        output = encrypt3(input, key16);
        System.out.println("Encrypted: " + output);
        output = decrypt3(output, key16);
        System.out.println("Decrypted: " + output);
    }

    // returns 16 byte init vector followed by encrypted data
    public static String encrypt3(final String input, final String key) {
        try {
            if (key.length() != 16)
                throw new RuntimeException("Key must be 16 characters");
            String iv = getInitVector();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encrypted = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(concat(iv.getBytes(StandardCharsets.UTF_8), encrypted));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // assumes 16 byte init vector followed by encrypted data
    public static String decrypt3(final String input, final String key) {
        try {
            if (key.length() != 16)
                throw new RuntimeException("Key must be 16 characters");
            byte[] encryptedBytes = Base64.getDecoder().decode(input);
            String iv = new String(encryptedBytes, 0, 16, StandardCharsets.UTF_8);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] decrypted = cipher.doFinal(Arrays.copyOfRange(encryptedBytes, 16, encryptedBytes.length));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encrypt2(final String input, final String key, final String iv) {
        try {
            var ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            var secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            var cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encrypted = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt2(final String input, final String key, final String iv) {
        try {
            var ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            var secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            var cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(input));
            return new String(original);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encrypt(final String input, final String key) {
        var textEncryptor = new AES256TextEncryptor();
        textEncryptor.setPassword(key);
        var myEncryptedText = textEncryptor.encrypt(input);
        return myEncryptedText;
    }

    public static String decrypt(final String input, final String key) {
        var textEncryptor = new AES256TextEncryptor();
        textEncryptor.setPassword(key);
        var decryptedText = textEncryptor.decrypt(input);
        return decryptedText;
    }

    // concatenate byte arrays into a single result
    private static byte[] concat(byte[] ...arrays) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] a:arrays) {
            outputStream.write(a);
        }

        return outputStream.toByteArray();
    }

    private static String getInitVector() {
        // return 16 random letters
        Random random = new Random();
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            int r = random.nextInt(26);
            buffer.append((char)(r + 97));  // 'a'
        }

        return buffer.toString();
    }
}
