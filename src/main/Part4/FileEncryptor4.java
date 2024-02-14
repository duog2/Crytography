import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileEncryptor4 {
    static PBEKeySpec pbeKeySpec;
    static PBEParameterSpec pbeParamSpec;
    static SecretKeyFactory keyFac;
    private static final Logger LOG = Logger.getLogger(FileEncryptor4.class.getSimpleName());
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_BLOWFISH = "Blowfish";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String operation = args[0];
        if (operation.equals("enc")) {
            String algorithm = args[1];
            int keylength = Integer.parseInt(args[2]);
            String password = args[3];
            String inputPath = args[4]; // ciphertext.enc
            String outputPath = args[5]; // plaintext.txt

            if(algorithm.equals(ALGORITHM_AES)) {
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16]; // You can adjust the salt length as needed
                random.nextBytes(salt);

                SecureRandom sr = new SecureRandom();
                byte[] initVec = new byte[16]; // Renamed to initVec for consistency
                sr.nextBytes(initVec);

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keylength);
                SecretKey tmp;
                try {
                    tmp = factory.generateSecret(spec);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }

                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), algorithm);
                System.out.println("Secret Key" + Base64.getEncoder().encodeToString(secret.getEncoded()));
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(initVec);
                cipher.init(Cipher.ENCRYPT_MODE, secret, ivParameterSpec);

                try (InputStream fin = new FileInputStream(inputPath);
                     OutputStream fout = new FileOutputStream(outputPath);
                     CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                    String fout_Algorithm = "AESSSSSS" + " " +keylength + "@@@@";
                    System.out.println(fout_Algorithm.getBytes(StandardCharsets.UTF_8).length);
                    fout.write(fout_Algorithm.getBytes(StandardCharsets.UTF_8));
                    fout.write(initVec);
                    fout.write(salt);
                    final byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fin.read(buffer)) != -1) {
                        cipherOut.write(buffer, 0, bytesRead);
                    }
                    LOG.info("Encryption finished");
                } catch (IOException e) {
                    LOG.log(Level.INFO, "Unable to encrypt", e);
                }
            } else if (algorithm.equals(ALGORITHM_BLOWFISH)) {
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[8];
                random.nextBytes(salt);

                SecureRandom sr = new SecureRandom();
                byte[] initVec = new byte[8];
                sr.nextBytes(initVec);

                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keylength);
                SecretKey tmp;
                try {
                    tmp = factory.generateSecret(spec);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), algorithm);
                Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(initVec);
                cipher.init(Cipher.ENCRYPT_MODE, secret, ivParameterSpec);
                try (InputStream fin = new FileInputStream(inputPath);
                     OutputStream fout = new FileOutputStream(outputPath);
                     CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher)) {
                     if(keylength < 100) {
                         String fout_Algorithm = "Blowfish" + 0 + keylength + "@@@@@";
                         fout.write(fout_Algorithm.getBytes(StandardCharsets.UTF_8));
                     }else if(keylength < 1000){
                         String fout_Algorithm = "Blowfish" + keylength + "@@@@@";
                         fout.write(fout_Algorithm.getBytes(StandardCharsets.UTF_8));

                     }
                    fout.write(salt);
                    fout.write(initVec); // Write IV as the first block of ciphertext
                    final byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fin.read(buffer)) != -1) {
                        cipherOut.write(buffer, 0, bytesRead);
                    }
                    } catch (IOException e) {
                    LOG.log(Level.INFO, "Unable to encrypt", e);
                }
                LOG.info("Encryption finished");
            }
        } else if (operation.equals("dec")) {
            String password = args[1];
            String inputPath = args[2]; // ciphertext.enc
            String outputPath = args[3]; // plaintext.txt
            byte[] algorithm_bytes = new byte[16];
            try (InputStream encryptedData = new FileInputStream(inputPath)) {
                int bytesRead = encryptedData.read(algorithm_bytes);
                if (bytesRead != 16) {
                    throw new IOException("Error reading IV from input file");
                }
            }
            String text = new String(algorithm_bytes, StandardCharsets.UTF_8);
            if (text.contains("AES")) {
                int keylength = Integer.parseInt(text.substring(9,12));
                try (InputStream encryptedData = new FileInputStream(inputPath)) {
                    encryptedData.skip(16);
                    byte[] ivBytes = new byte[16];
                    int bytesRead = encryptedData.read(ivBytes);
                    if (bytesRead != 16) {
                        throw new IOException("Error reading IV from input file");
                    }
                    //encryptedData.skip(16);
                    byte[] saltBytes = new byte[16];
                    int saltRead = encryptedData.read(saltBytes);
                    if (saltRead != 16) {
                        throw new IOException("Error reading IV from input file");
                    }
                    //encryptedData.skip(16);

                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536,keylength);
                    SecretKey tmp;
                    try {
                        tmp = factory.generateSecret(spec);
                    } catch (InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    }
                    SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
                    cipher.init(Cipher.DECRYPT_MODE, secret, ivParameterSpec);

                    try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                         OutputStream decryptedOut = new FileOutputStream(outputPath)) {
                        final byte[] buffer = new byte[1024];
                        while ((bytesRead = decryptStream.read(buffer)) != -1) {
                            decryptedOut.write(buffer, 0, bytesRead);
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(FileEncryptor4.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
                    }
                } catch (IOException e) {
                    LOG.log(Level.INFO, "Unable to read IV from input file", e);
                }
                LOG.info("Decryption complete");
            }
            else if(text.contains("Blowfish")){
                int keylength = Integer.parseInt(text.substring(8,11));
                System.out.println(keylength);
                try (InputStream encryptedData = new FileInputStream(inputPath)) {
                    encryptedData.skip(16);
                    byte[] saltbytes = new byte[8];
                    int saltread = encryptedData.read(saltbytes);
                    if (saltread != 8) {
                        throw new IOException("Error reading IV from input file");
                    }
                    byte[] ivBytes = new byte[8];
                    int bytesRead = encryptedData.read(ivBytes);
                    if (bytesRead != 8) {
                        throw new IOException("Error reading IV from input file");
                    }
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    KeySpec spec = new PBEKeySpec(password.toCharArray(), saltbytes, 65536, keylength);
                    SecretKey tmp;
                    try {
                        tmp = factory.generateSecret(spec);
                    } catch (InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    }
                    SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "Blowfish");

                    Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
                    cipher.init(Cipher.DECRYPT_MODE, secret, ivParameterSpec);

                    try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                         OutputStream decryptedOut = new FileOutputStream(outputPath)) {
                        final byte[] buffer = new byte[1024];
                        while ((bytesRead = decryptStream.read(buffer)) != -1) {
                            decryptedOut.write(buffer, 0, bytesRead);
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(FileEncryptor4.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
                    }
                } catch (IOException e) {
                    LOG.log(Level.INFO, "Unable to read IV from input file", e);
                }
                LOG.info("Decryption complete");
            }
        } else if (operation.equals("info")) {
            String output = args[1];
            byte[] algorithm_bytes = new byte[16];
            try (InputStream encryptedData = new FileInputStream(output)) {
                int bytesRead = encryptedData.read(algorithm_bytes);
                if (bytesRead != 16) {
                    throw new IOException("Error reading IV from input file");
                }
            }
            String text = new String(algorithm_bytes, StandardCharsets.UTF_8);
            if(text.contains("AES")) {
                System.out.println("Algorithm: " + text.substring(0, 7));
            } else if (text.contains("Blowfish")) {
                int key = Integer.parseInt(text.substring(8,11));
                if(key > 100) {
                    System.out.println("Algorithm: " + text.substring(0, 8) + " " + key);
                }
                else if(key < 100){
                    System.out.println("Algorithm: " + text.substring(0, 8) + " " + text.substring(9, 11));
                }
            }
        }
    }
}
