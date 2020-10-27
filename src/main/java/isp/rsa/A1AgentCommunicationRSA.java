package isp.rsa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using
 * a RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the
 * isp.steganography.ImageSteganography class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // Create two public-secret key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKeyPair = kpg.generateKeyPair();
        final KeyPair aliceKeyPair = kpg.generateKeyPair();

        final Environment env = new Environment();

        final int numberOfRepetitions = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfRepetitions; i++) {
                    send("bob", encrypt("Hi. Kisses, Alice", bobKeyPair.getPublic()));
                    String received = decrypt(receive("bob"), aliceKeyPair.getPrivate());
                    print("Received MSG: %s", received);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfRepetitions; i++) {
                    String received = decrypt(receive("alice"), bobKeyPair.getPrivate());
                    print("Received MSG: %s", received);
                    send("alice", encrypt("Ack. Kisses, Bob.", aliceKeyPair.getPublic()));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static byte[] encrypt(String message, PublicKey publicKey) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        final String algorithm = "RSA/ECB/OAEPPadding";
        final byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

        final Cipher encrypt = Cipher.getInstance(algorithm);
        encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
        return encrypt.doFinal(plaintext);
    }

    public static String decrypt(final byte[] ciphertext, PrivateKey privateKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
        final String algorithm = "RSA/ECB/OAEPPadding";
        final Cipher decrypt = Cipher.getInstance(algorithm);
        decrypt.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decrypt.doFinal(ciphertext));
    }
}
