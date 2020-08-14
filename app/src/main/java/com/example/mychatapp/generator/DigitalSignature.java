package com.example.mychatapp.generator;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

/***************************************************************************************
 *    Title: <Java Cryptography - Creating Signature>
 *    Author: <tutorialspoint>
 *    Date: <2020/08/14>
 *    Availability: <https://www.tutorialspoint.com/java_cryptography/java_cryptography_creating_signature.htm>
 ***************************************************************************************/

public class DigitalSignature {
    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    public static String GenerateSignature(String data, String modulus, String exponent) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        //convert String to BigInteger
        BigInteger m = new BigInteger(modulus);
        BigInteger e = new BigInteger(exponent);

        //using modulus and exponent to regenerate public or private key.
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(m, e);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(spec);

        //create signature object
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        //using the private key to sign the data(the hashed message)
        signature.update(data.getBytes());
        byte[] sign = signature.sign();

        //convert the byte array to hex String object
        String s = byteToHex(sign);

        return s;
    }

    //https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
    //generate the key pair that includes public and private key
    public static KeyPair generateKeypair() throws NoSuchAlgorithmException {
        //create keypair generator object
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //initializing the keypair generator
        keyPairGenerator.initialize(2048);
        //generator public & private key pair
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return pair;
    }

    //convert byte[] to hex-string
    public static String byteToHex(byte[] b){
        char[] chars = new char[b.length * 2];
        for (int i = 0; i < b.length; i++){
            int value = b[i] & 0xFF;
            chars[i*2] = HEX_CHARS[value >>> 4];
            chars[i*2+1] = HEX_CHARS[value & 0x0F];
        }
        return new String(chars);
    }

    //convert hex-string to byte[]
    public static byte[] toByteArray(String hexString) {
        String hex = hexString.toLowerCase();
        final byte[] bytes = new byte[hex.length() >> 1];
        int index = 0;
        for (int i = 0; i < hex.length(); i++) {
            if (index  > hex.length() - 1)
                return bytes;
            byte high = (byte) (Character.digit(hex.charAt(index), 16) & 0xFF);
            byte low = (byte) (Character.digit(hex.charAt(index + 1), 16) & 0xFF);
            bytes[i] = (byte) (high << 4 | low);
            index += 2;
        }
        return bytes;
    }

}
