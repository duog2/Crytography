import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 *
 * @author Duong Tran
 */
public class FileEncryptor5 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor5.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        vPNG png = new vPNG(16);
        byte[] initVector = new byte[16];
        for (int i = 0; i < initVector.length; i++) {
            initVector[i] = png.next();
        }
        String operation = args[0];
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        if (operation.equals("enc")) {
            String inputPath = args[1];
            String outputPath = args[2];
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            System.out.println("Secret key: " + Base64.getEncoder().encodeToString(skeySpec.getEncoded()));
            System.out.println("Vulnerable Iv: " + Base64.getEncoder().encodeToString(iv.getIV()));
            try (InputStream fin = new FileInputStream(inputPath);
                 OutputStream fout = new FileOutputStream(outputPath);
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }
            LOG.info("Encryption finished");
        }
        if (operation.equals("dec")) {
            String base64Key = args[1];
            String base64IV = args[2];
            byte[] keys = Base64.getDecoder().decode(base64Key);
            byte[] ivs = Base64.getDecoder().decode(base64IV);

            Cipher cipher = Cipher.getInstance(CIPHER);
            SecretKeySpec SkeySpec = new SecretKeySpec(keys, ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivs);
            cipher.init(Cipher.DECRYPT_MODE, SkeySpec, ivParameterSpec);
            System.out.println("Second IV:" + Base64.getEncoder().encodeToString(ivParameterSpec.getIV()));

            String inputPath = args[3]; // ciphertext.enc
            String outputPath = args[4]; // plaintext.txt

            try (InputStream encryptedData = Files.newInputStream(Paths.get(inputPath));
                 CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                 OutputStream decryptedOut = Files.newOutputStream(Paths.get(outputPath))) {

                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            }  catch (IOException ex) {
                Logger.getLogger(FileEncryptor5.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }
            LOG.info("Decryption complete");
        }
    }
}