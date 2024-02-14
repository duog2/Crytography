import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor2 {

    //default password: lJkvq8XppwVByZRc3TCBKQ==
    private static final Logger LOG = Logger.getLogger(FileEncryptor2.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String operation = args[0];
        String base64Key = args[1];
        byte[] keys = Base64.getDecoder().decode(base64Key);

        SecretKeySpec skeySpec = new SecretKeySpec(keys, ALGORITHM);

        String inputPath = args[2]; // plaintext.txt
        String outputPath = args[3]; // ciphertext.enc

        if (operation.equals("enc")) {
            SecureRandom sr = new SecureRandom();
            byte[] init_vec = new byte[16];
            sr.nextBytes(init_vec);

            Cipher cipher = Cipher.getInstance(CIPHER);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(init_vec);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);

            try (InputStream fin = new FileInputStream(inputPath);
                 OutputStream fout = new FileOutputStream(outputPath);
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                fout.write(init_vec); // Write IV as the first block of ciphertext

                final byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fin.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }
            LOG.info("Encryption finished");
        } else if (operation.equals("dec")) {
            try (BufferedInputStream encryptedData = new BufferedInputStream(new FileInputStream(inputPath))) {
                byte[] ivBytes = new byte[16];
                int bytesRead = encryptedData.read(ivBytes);
                if (bytesRead != 16) {
                    throw new IOException("Error reading IV from input file");
                }
                Cipher cipher = Cipher.getInstance(CIPHER);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);

                try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                     OutputStream decryptedOut = new FileOutputStream(outputPath)) {
                    final byte[] buffer = new byte[1024];
                    while ((bytesRead = decryptStream.read(buffer)) != -1) {
                        decryptedOut.write(buffer, 0, bytesRead);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(FileEncryptor2.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
                }
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to read IV from input file", e);
            }
            LOG.info("Decryption complete");
        }
    }
}
