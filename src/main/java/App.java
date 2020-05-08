import org.jasypt.util.text.AES256TextEncryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

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
}
