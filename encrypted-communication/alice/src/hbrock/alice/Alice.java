package hbrock.alice;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Main class for the Alice program in PA3.
 *
 * Alice requests Bob's public key, verifies the key, then sends an encrypted message to Bob
 * and shuts down.
 *
 * @author Hannah Brock
 */
public class Alice {
    // key request message
    private static final String KEY_REQUEST = "REQUEST KEY\n";

    private PrivateKey privKey;
    private PublicKey veriKey;
    private final int logLevel;
    private Socket bob;
    private PublicKey bobKey;

    /**
     * Creates a new instance of Alice using the provided key files
     * @param privKeyFile Alice's private key file
     * @param veriKeyFile Third party public key used to verify Bob's public key
     * @param logLevel Verbosity of the log
     */
    public Alice(String privKeyFile, String veriKeyFile, int logLevel) {
        this.logLevel = logLevel;
        log("Log level set to " + logLevel, logLevel);
        loadKeys(privKeyFile, veriKeyFile);
    }

    /**
     * Loads Alice's keys from files
     * @param privKeyFile Alice's private key
     * @param veriKeyFile Third party public key used to verify Bob's public key
     */
    private void loadKeys(String privKeyFile, String veriKeyFile) {
        log("Loading Alice's private key from '" + privKeyFile + "'", 1);
        privKey = (PrivateKey)loadKey(privKeyFile, false);
        log("Loading the third party verification public key from '" + veriKeyFile + "'", 1);
        veriKey = (PublicKey)loadKey(veriKeyFile, true);
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
            return key;
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
     * Create a connection to Bob
     * @param bobHost Bob's host
     * @param bobPort Bob's port
     * @return Socket connected to Bob or null if something went wrong
     */
    private Socket connectToBob(String bobHost, int bobPort) {
        log("Connecting to Bob at " + bobHost + ":" + bobPort, 1);
        try {
            return new Socket(bobHost, bobPort);
        } catch (IOException e) {
            log("Unable to connect to Bob at " + bobHost + ":" + bobPort, 0);
            return null;
        }
    }

    /**
     * Verifies a key and certificate pair
     * @param key the key
     * @param sig the signature/certificate of the key
     * @return true if verified
     */
    private boolean verifyKey(byte[] key, byte[] sig) {
        log("Verifying Bob's key", 1);
        log("Key bytes:", key, 1);
        log("Signature bytes:", sig, 1);
        try {
            Signature sigVer = Signature.getInstance("SHA1withRSA");
            sigVer.initVerify(veriKey);
            sigVer.update(key, 0, key.length);
            return sigVer.verify(sig);
        } catch (Exception e) {
            log("Unable to complete verification of key: " + e.getMessage(), 0);
        }
        return false;
    }

    /**
     * Request Bob's public key
     * @return Bob's key or null if something went wrong
     */
    private PublicKey requestKey() {
        if (bob.isConnected()) {
            log("Requesting Bob's public key", 1);
            try {
                OutputStream os = bob.getOutputStream();
                os.write(KEY_REQUEST.getBytes());
                os.flush();

                DataInputStream is = new DataInputStream(bob.getInputStream());
                int len = is.readInt();
                byte[] key = new byte[len];
                is.read(key, 0, len);
                log("Received key from Bob", 1);
                len = is.readInt();
                byte[] sig = new byte[len];
                is.read(sig, 0, len);
                log("Received certificate from Bob", 1);

                log("Key bytes:", key, 1);
                log("Signature bytes:", sig, 1);
                boolean verified = verifyKey(key, sig);
                if (!verified) {
                    log("Bob's certificate is not valid!", 1);
                    return null;
                }
                log("Bob's key is verified", 1);

                X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(spec);
            } catch (IOException e) {
                log("Unable to receive data on socket", 0);
            } catch (NoSuchAlgorithmException e) {
                log("Unable to decode Bob's public key: " + e.getMessage(), 0);
            } catch (InvalidKeySpecException e) {
                log("Unable to decode Bob's public key: " + e.getMessage(), 0);
            }
        }
        return null;
    }

    /**
     * Generate key for message encryption
     * @return the generated key
     */
    private SecretKey generate3DESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            keyGen.init(168); // use 3 keys
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            log("Could not generate 3DES encryption key", 0);
        }
        return null;
    }

    /**
     * Combine two byte arrays and include their lengths
     * @param b1 first array
     * @param b2 second array
     * @return the combined array with length markers
     */
    private byte[] combineByteArrays(byte[] b1, byte[] b2) {
        ByteBuffer toEnc = ByteBuffer.allocate(4 + b1.length + 4 + b2.length);
        toEnc.putInt(b1.length);
        toEnc.put(b1);
        toEnc.putInt(b2.length);
        toEnc.put(b2);
        return toEnc.array();
    }

    /**
     * Encrypt bytes using Bob's public key
     * @param msg bytes to encrypt
     * @return the encrypted bytes or null
     */
    private byte[] encryptBobsKey(byte[] msg) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, bobKey);
            return cipher.doFinal(msg);
        } catch (Exception e) {
            log("Unable to encrypt with Bob's public key: " + e.getMessage(), 0);
        }
        return null;
    }

    /**
     * Encrypts and sends the message to Bob
     * @param msg the message to send
     */
    private void sendMsg(String msg) {
        log("Signing message (SHA1 digest with RSA signature)", 1);

        // Generate message hash + sign it (all done in a Signature here)
        byte[] msgBytes;
        byte[] sig;
        try {
            Signature sigGen = Signature.getInstance("SHA1withRSA");
            sigGen.initSign(privKey);
            msgBytes = msg.getBytes();
            sigGen.update(msgBytes, 0, msgBytes.length);
            sig = sigGen.sign();
        } catch (Exception e) {
            log("Failed to encrypt message: " + e.getMessage(), 0);
            return;
        }

        if (msgBytes == null || sig == null)
            return;

        log("Message: " + msg, 1);
        log("Signature bytes:", sig, 1);

        // Combine the message and signature
        byte[] toEnc = combineByteArrays(msgBytes, sig);

        // Create a secret key
        log("Generating secret key", 1);
        SecretKey key = generate3DESKey();
        if (key == null) {
            log("Could not generate secret key", 0);
            return;
        }
        log("Key bytes:", key.getEncoded(), 1);

        // Create cipher + IV for 3DES encryption
        Cipher cipher;
        IvParameterSpec iv;
        try {
            cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            SecureRandom sr = new SecureRandom();
            byte[] ivBytes = new byte[8];
            sr.nextBytes(ivBytes);
            iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } catch (Exception e) {
            log("Could not generate 3DES cipher: " + e.getMessage(), 0);
            return;
        }
        log("IV bytes:", iv.getIV(), 1);

        // Encrypt the message + signature with 3DES
        log("Encrypting message: " + msg, 1);
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(toEnc);
        } catch (Exception e) {
            log("Unable to encrypt message: " + e.getMessage(), 0);
            return;
        }
        log("Encrypted message package:", encrypted, 1);

        // Encrypt secret key + IV with Bob's public key
        log("Encrypting secret key + IV with Bob's public key", 1);
        byte[] keyPlusIV = encryptBobsKey(combineByteArrays(key.getEncoded(), iv.getIV()));
        if (keyPlusIV == null)
            return;
        log("Encrypted key + IV:", keyPlusIV, 1);

        // Send the whole thing off to Bob
        log("Sending message to Bob", 1);
        byte[] finalBytes = combineByteArrays(encrypted, keyPlusIV);
        try {
            OutputStream os = bob.getOutputStream();
            os.write(finalBytes);
            os.flush();
        } catch (IOException e) {
            log("Failed to send message: " + e.getMessage(), 0);
        }
    }

    /**
     * Run Alice
     * @param bobHost Bob's host
     * @param bobPort Bob's port
     */
    public void run(String bobHost, int bobPort, String msgFile) {
        if (privKey == null || veriKey == null) {
            log("Missing one or more keys. Unable to run Alice.", 0);
            return;
        }
        if (bobHost == null || bobPort < 0) {
            log("Missing Bob host or port. Unable to run Alice.", 0);
            return;
        }

        // open socket to bob
        bob = connectToBob(bobHost, bobPort);
        if (bob == null) {
            log("Unable to connect to Bob, shutting down", 0);
            return;
        }

        // get Bob's public key and verify
        bobKey = requestKey();
        if (bobKey == null) {
            log("Unable to get Bob's public key", 0);
            return;
        }

        // Get message to send
        String msg = "";
        try {
            if (msgFile == null) {
                BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("Enter message to send:");
                msg = console.readLine();
            } else {
                BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(msgFile),
                                                                             Charset.forName("UTF-8")));
                String line = "";
                while ((line = br.readLine()) != null) {
                    msg += line;
                }
                br.close();
            }
        } catch (Exception e) {
            log("Unable to read input: " + e.getMessage(), 0);
        }

        // Send the message
        if (msg != null && msg.length() > 0) {
            sendMsg(msg);
            log("Sent message, shutting down", 1);
        } else {
            log("No message to send, shutting down", 0);
        }

        try {
            bob.close();
        } catch (IOException e) {
            log("Failure closing socket: " + e.getMessage(), 0);
        }
    }

    /**
     * Print usage information
     */
    public static void printUsage(){
        System.out.println("Usage: java Alice [options]");
        System.out.println("Options:");
        System.out.println("-bobHost <host> \t REQUIRED. Hostname where the Bob program is running");
        System.out.println("-bobPort <port> \t REQUIRED. Port Bob is running on");
        System.out.println("-msg <file> \t OPTIONAL. File containing message to send. Defaults to console input.");
        System.out.println("-v \t OPTIONAL. Use this option for verbose output");
        System.out.println("-privKey <file> \t OPTIONAL. Specify Alice's private key file. " +
                            "Defaults to 'alice_priv.der'");
        System.out.println("-veriKey <file> \t OPTIONAL. Specify the third party verification public key file. " +
                                   "Defaults to 'verification_pub.der'");
    }

    /**
     * Entry point for Alice program
     * @param args Command line args - must include Bob's host/port
     */
    public static void main(String[] args) {
        // default key files and log level
        String privKey = "alice_priv.der";
        String veriKey = "verification_pub.der";
        String msgFile = null;
        int logLevel = 0;

        // parse command line args
        String bobHost = null;
        int bobPort = -1;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-v"))
                logLevel++;
            else if (args[i].equals("-bobHost") && i != (args.length-1)) {
                bobHost = args[++i];
            }
            else if (args[i].equals("-bobPort") && i != (args.length-1)) {
                try {
                    bobPort = Integer.parseInt(args[++i]);
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
            } else if (args[i].equals("-msg") && i != (args.length-1)) {
                msgFile = args[++i];
            }
            else {
                printUsage();
                return;
            }
        }

        if (bobHost == null || bobPort == -1) {
            System.err.println("Invalid usage: Bob's host and port must be specified");
            return;
        }

        // create Alice
        Alice a = new Alice(privKey, veriKey, logLevel);

        // run Alice
        a.run(bobHost, bobPort, msgFile);
    }
}
