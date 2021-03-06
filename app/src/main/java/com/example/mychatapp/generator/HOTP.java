package com.example.mychatapp.generator;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HOTP {

    //function to generate a random counter
    public static long Counter(int length){
        String Number = "1234567890";
        Random rand = new Random();

        char[] array = new char[length];
        for (int i = 0; i < length; i++){
            array[i] = Number.charAt(rand.nextInt(Number.length()));
        }
        String string = new String(array);
        return Long.parseLong(string);
    }

    //function to generate a random seed
    public static byte[] Seed(int length){
        //available characters
        String Upper_Case_letter = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String Lower_Case_letter = "abcdefghijklmnopqrstuvwxyz";
        String Number = "1234567890";
        String Symbol = "!@#$%^&*_=+-/.?<>)";

        String characters = Upper_Case_letter + Lower_Case_letter + Number + Symbol;

        Random rand = new Random();

        //create char array for the random otp
        char[] array = new char[length];
        for (int i = 0; i < length; i++){
            array[i] = characters.charAt(rand.nextInt(characters.length()));
        }
        String string = new String(array);
        return string.getBytes();
    }

    //HMAC-SHA1 function
    //using secret key and the message to create Hash-based Message Authentication Code
    private static byte[] HMAC_SHA1(byte[] seed, byte[] message){
        try {
            Mac hmac_sha1 = Mac.getInstance("HmacSHA1");
            SecretKeySpec secretKeySpec = new SecretKeySpec(seed, "HmacSHA1");
            hmac_sha1.init(secretKeySpec);
            return hmac_sha1.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /***************************************************************************************
     *    Title: <HOTP: An HMAC-Based One-Time Password Algorithm>
     *    Copyright (C) The Internet Society (2005).
     *    Date: <2020/08/14>
     *    Availability: <https://tools.ietf.org/html/rfc4226>
     ***************************************************************************************/

    public static String generateOTP(byte[] secret, long movingFactor){
        //put movingFactors value into text byte array
        String result;
        byte[] text = new byte[8];

        for (int i = text.length-1; i>=0; i--){
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        //compute hmac hash
        byte[] hash = HMAC_SHA1(secret, text);

        assert hash != null;
        result = new String(hash, StandardCharsets.UTF_8);

        return result;
    }
}
