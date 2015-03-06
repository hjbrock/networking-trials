package hbrock.bob;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Main class for the Bob Program
 *
 * @author Hannah Brock
 */
public class Bob {
    private static final String KEY_REQUEST = "REQUEST KEY";

    private PublicKey pubKey;
    private PrivateKey privKey;
    private PrivateKey veriKey;
    private PublicKey aliceKey;
    private int logLevel;
    ServerSocket bob;

    /**
     * Creates a new instance of Bob using the provided key files
     * @param privKeyFile Bob's private key file
     * @param veriKeyFile Third party public key used to verify Bob's public key
     * @param logLevel Verbosity of the log
     */
    public Bob(String pubKeyFile, String privKeyFile, String veriKeyFile, String aliceKeyFile, int logLevel) {
        this.logLevel = logLevel;
        log("Log level set to " + logLevel, logLevel);
        loadKeys(pubKeyFile, privKeyFile, veriKeyFile, aliceKeyFile);
    }

    /**
     * Loads Bob's keys from files
     * @param privKeyFile Bob's private key
     * @param veriKeyFile Third party public key used to verify Bob's public key
     */
    private void loadKeys(String pubKeyFile, String privKeyFile, String veriKeyFile, String aliceKeyFile) {
        log("Loading Bob's public key from '" + pubKeyFile + "'", 1);
        pubKey = (PublicKey)loadKey(pubKeyFile, true);
        log("Loading Bob's private key from '" + privKeyFile + "'", 1);
        privKey = (PrivateKey)loadKey(privKeyFile, false);
        log("Loading the third party verification private key from '" + veriKeyFile + "'", 1);
        veriKey = (PrivateKey)loadKey(veriKeyFile, false);
        log("Loading Alice's public key from '" + aliceKeyFile + "'", 1);
        aliceKey = (PublicKey)loadKey(aliceKeyFile, true);
    }

    /**
     * Loads a single key from a file
     * @param keyFile key to load
     * @param publicKey whether or not the key is a public key
     * @return the key, or null if the key could not be loaded
     */
    private Key loadKey(String keyFile, boolean publicKey) {
        FileInputStream fis;
        Key key = null;

        try {
            fis = new FileInputStream(keyFile);
        } catch (FileNotFoundException e) {
            log("Could not open '" + keyFile + "'", 0);
            return null;
        }

        try {
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            if (publicKey) {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                key = keyFactory.generatePublic(spec);
            } else {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                key = keyFactory.generatePrivate(spec);
            }
        } catch (Exception e) {
            log("Could not read key from '" + keyFile + "': " + e.getMessage(), 0);
        } finally {
            closeFIS(fis);
        }
        return key;
    }

    /**
     * Attempt to close a FileInputStream
     * @param fis FIS to close
     */
    private void closeFIS(FileInputStream fis) {
        try {
            fis.close();
        } catch (IOException e) {
            log("Error closing file input", 0);
        }
    }

    /**
     * Log a message at the given log level.
     * @param msg message to log
     * @param logLevel log level
     */
    private void log(String msg, int logLevel) {
        if (logLevel <= this.logLevel) {
            System.out.println("<Log (level " + logLevel + ")> " + msg);
        }
    }

    /**
     * Log a message and the contents of a byte array as a hex string
     * @param msg message to log
     * @param bytes bytes to log
     * @param logLevel log level
     */
    private void log(String msg, byte[] bytes, int logLevel) {
        if (logLevel <= this.logLevel) {
            StringBuilder sb = new StringBuilder();
            for(byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            System.out.println(msg + " " + sb.toString());
        }
    }

    /**
     * Read a line from the given socket
     * @param s the socket to read from
     * @return the line (may be null)
     */
    private String receiveLine(Socket s) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            return in.readLine();
        } catch (IOException e) {
            log("Unable to read from socket: " + e.getMessage(), 0);
            return null;
        }
    }

    /**
     * Split the array into two arrays, b1 and b2
     * @param array array to split
     * @param b1 first portion of array
     * @param b2 second portion of array
     */
    private boolean splitArray(byte[] array, ByteArrayOutputStream b1, ByteArrayOutputStream b2) {
        DataInputStream is = new DataInputStream(new ByteArrayInputStream(array));
        try {
            int len = is.readInt();
            byte[] msg = new byte[len];
            is.read(msg, 0, len);
            b1.write(msg);

            len = is.readInt();
            msg = new byte[len];
            is.read(msg, 0, len);
            b2.write(msg);
        } catch (IOException e) {
           log("Unable to read message: " + e.getMessage(), 0);
            return false;
        }
        return true;
    }

    /**
     * Decrypts a received message
     * @param encrypted the encrypted message
     * @param encryptedSecret the encrypted secret and IV
     * @return the clear text
     */
    private String decryptMsg(byte[] encrypted, byte[] encryptedSecret) {
        // decrypt secret and split it
        log("Decrypting secret key + iv", 1);
        log("Encrypted value:", encryptedSecret, 1);
        Cipher cipher;
        byte[] decryptedSecret;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            decryptedSecret = cipher.doFinal(encryptedSecret);
        } catch (Exception e) {
            log("Unable to encrypt with Bob's private key: " + e.getMessage(), 0);
            return null;
        }

        // split secret key + IV
        ByteArrayOutputStream b1 = new ByteArrayOutputStream();
        ByteArrayOutputStream b2 = new ByteArrayOutputStream();
        if (!splitArray(decryptedSecret, b1, b2)) {
            log("Unable to split secret and IV", 0);
            return null;
        }
        log("Decrypted secret:", b1.toByteArray(), 1);
        log("Decrypted IV:", b2.toByteArray(), 1);
        SecretKey key = new SecretKeySpec(b1.toByteArray(), 0, b1.size(), "DESede");
        IvParameterSpec iv = new IvParameterSpec(b2.toByteArray());

        // decrypt message package
        log("Decrypting message using secret key + IV", 1);
        log("Encrypted message package:", encrypted, 1);
        byte[] decrypted;
        try {
            cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            decrypted = cipher.doFinal(encrypted);
        } catch (Exception e) {
            log("Failed to decrypt 3DES encrypted package: " + e.getMessage(), 0);
            return null;
        }

        // split message into actual message and signature
        b1 = new ByteArrayOutputStream();
        b2 = new ByteArrayOutputStream();
        if (!splitArray(decrypted, b1, b2)) {
            log("Unable to split decrypted message", 0);
            return null;
        }

        String msg;
        try {
            msg = b1.toString("UTF-8");
        } catch (UnsupportedEncodingException e) {
            log("Unable to convert byte message to string: " + e.getMessage(), 0);
            return null;
        }
        log("Decrypted message: " + msg, 1);
        log("Decrypted signature:", b2.toByteArray(), 1);

        // verify signature
        log("Verifying signature", 1);
        boolean verify;
        try {
            Signature sigVer = Signature.getInstance("SHA1withRSA");
            sigVer.initVerify(aliceKey);
            sigVer.update(b1.toByteArray());
            verify = sigVer.verify(b2.toByteArray());
        } catch (Exception e) {
            log("Unable to verify signature: " + e.getMessage(), 0);
            return null;
        }

        if (verify) {
            log("Signature valid!", 1);
            return msg;
        } else {
            log("Signature not valid! Abandoning message.", 0);
        }
        return null;
    }

    /**
     * Read bytes from a socket
     */
    private void receiveMsg(Socket s) {
        try {
            DataInputStream is = new DataInputStream(s.getInputStream());

            // get encrypted message
            int len = is.readInt();
            if (len < 0) {
                log("Unable to retrieve message", 0);
                return;
            }
            byte[] encrypted = new byte[len];
            len = is.read(encrypted, 0, len);
            if (len < 0) {
                log("Socket closed, full message not received", 0);
                return;
            }

            // get encrypted key + IV
            len = is.readInt();
            if (len < 0) {
                log("Unable to retrieve message", 0);
                return;
            }
            byte[] encryptedSecret = new byte[len];
            len = is.read(encryptedSecret, 0, len);
            if (len < 0) {
                log("Socket closed, full message not received", 0);
                return;
            }

            String msg = decryptMsg(encrypted, encryptedSecret);
            if (msg != null)
                log("Received message from Alice with text: '" + msg + "'", 0);
        } catch (IOException e) {
            log("Could not retrieve message: " + e.getMessage(), 0);
        }
    }

    /**
     * Send Bob's public key to the given socket
     * @param s the socket
     * @return true if successfully sent
     */
    private boolean sendKey(Socket s) {
        log("Signing public key", 1);
        log("Key bytes:", pubKey.getEncoded(), 1);
        try {
            Signature sigGen = Signature.getInstance("SHA1withRSA");
            sigGen.initSign(veriKey);
            sigGen.update(pubKey.getEncoded());
            byte[] sig = sigGen.sign();
            log("Signature bytes:", sig, 1);

            log("Sending key and certificate to Alice", 1);
            DataOutputStream os = new DataOutputStream(s.getOutputStream());
            int len = pubKey.getEncoded().length;
            os.writeInt(len);
            os.write(pubKey.getEncoded(), 0, len);
            len = sig.length;
            os.writeInt(len);
            os.write(sig, 0, len);
            os.flush();
        } catch (Exception e) {
            log("Could not generate signature for public key: " + e.getMessage(), 0);
            return false;
        }
        return true;
    }

    /**
     * Run Bob
     */
    public void run(int port) {
        try {
            bob = new ServerSocket(port);

            log("Waiting for message", 0);
            Socket alice = bob.accept();

            String line = receiveLine(alice);
            if (line != null && line.equals(KEY_REQUEST)) {
                log("Received key request from Alice", 1);
                sendKey(alice);
            }
            receiveMsg(alice);
        } catch (IOException e) {
            log("Error encountered: " + e.getMessage(), 0);
        } finally {
            try {
                log("Shutting down", 0);
                bob.close();
            } catch (IOException e) {
                log("Error closing socket: " + e.getMessage(), 0);
            }
        }
    }

    /**
     * Print usage information
     */
    public static void printUsage(){
        System.out.println("Usage: java Bob [options]");
        System.out.println("Options:");
        System.out.println("-port <port> \t REQUIRED. Specify the port Bob should run on");
        System.out.println("-v \t OPTIONAL. Use this option for verbose output");
        System.out.println("-pubKey <file> \t OPTIONAL. Specify Bob's public key file. " +
                                   "Defaults to 'bob_pub.der'");
        System.out.println("-privKey <file> \t OPTIONAL. Specify Bob's private key file. " +
                                   "Defaults to 'bob_priv.der'");
        System.out.println("-veriKey <file> \t OPTIONAL. Specify the third party verification private key file. " +
                                   "Defaults to 'verification_priv.der'");
        System.out.println("-aliceKey <file> \t OPTIONAL. Specify Alice's public key file. " +
                                   "Defaults to 'alice_pub.der'");
    }

    /**
     * Entry point for Bob program
     * @param args command line arguments, must at least include Bob's port
     */
    public static void main(String[] args) {
        // default key files and log level
        String privKey = "bob_priv.der";
        String pubKey = "bob_pub.der";
        String veriKey = "verification_priv.der";
        String aliceKey = "alice_pub.der";
        int logLevel = 0;

        // parse command line args
        int port = -1;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-v"))
                logLevel++;
            else if (args[i].equals("-port") && i != (args.length-1)) {
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid argument: Bob's port must be an integer");
                    return;
                }
            }
            else if (args[i].equals("-privKey") && i != (args.length-1)) {
                privKey = args[++i];
            }
            else if (args[i].equals("-veriKey") && i != (args.length-1)) {
                veriKey = args[++i];
            }
            else if (args[i].equals("-pubKey") && i != (args.length-1)) {
                pubKey = args[++i];
            }
            else if (args[i].equals("-aliceKey") && i != (args.length-1)) {
                aliceKey = args[++i];
            }
            else {
                printUsage();
                return;
            }
        }

        if (port == -1) {
            System.err.println("Invalid usage: Bob's port must be specified");
            return;
        }

        // create Bob
        Bob b = new Bob(pubKey, privKey, veriKey, aliceKey, logLevel);

        // run Bob
        b.run(port);
    }
}
