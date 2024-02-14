import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileEncryptor3 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor3.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String operation = args[0];
        String password = args[1];

        String inputPath = args[2]; // ciphertext.enc
        String outputPath = args[3]; // plaintext.txt

        if (operation.equals("enc")) {
            SecureRandom sr = new SecureRandom();
            byte[] initVec = new byte[16]; // Renamed to initVec for consistency
            sr.nextBytes(initVec);

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16]; // You can adjust the salt length as needed
            random.nextBytes(salt);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp;
            try {
                tmp = factory.generateSecret(spec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
            // Moved cipher initialization here
            System.out.println("Secret key:" + Base64.getEncoder().encodeToString(secret.getEncoded()));

            Cipher cipher = Cipher.getInstance(CIPHER);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVec);
            cipher.init(Cipher.ENCRYPT_MODE, secret, ivParameterSpec);

            try(InputStream fin = new FileInputStream(inputPath);
                 OutputStream fout = new FileOutputStream(outputPath);
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                 fout.write(initVec); // Write IV as the first block of ciphertext
                 fout.write(salt);

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
            byte[] ivBytes = new byte[16];
            try (InputStream encryptedData = new FileInputStream(inputPath)) {
                int bytesRead = encryptedData.read(ivBytes);
                if (bytesRead != 16) {
                    throw new IOException("Error reading IV from input file");
                }
                byte [] salt = new byte[16];
                //encryptedData.skip(16);
                int saltread = encryptedData.read(salt);
                if (saltread != 16) {
                    throw new IOException("Error reading IV from input file");
                }
                //encryptedData.skip(16);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
                SecretKey tmp;
                try {
                    tmp = factory.generateSecret(spec);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

                Cipher cipher = Cipher.getInstance(CIPHER);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
                cipher.init(Cipher.DECRYPT_MODE, secret, ivParameterSpec);

                try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                     OutputStream decryptedOut = new FileOutputStream(outputPath)) {
                    final byte[] buffer = new byte[1024];
                    while ((bytesRead = decryptStream.read(buffer)) != -1) {
                        decryptedOut.write(buffer, 0, bytesRead);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(FileEncryptor3.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
                }
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to read IV from input file", e);
            }
            LOG.info("Decryption complete");
        }
    }
}
