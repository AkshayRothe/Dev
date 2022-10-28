// ============================================================================
//
// Copyright (C) 2006-2019 Talend Inc. - www.talend.com
//
// This source code is available under agreement available at
// %InstallDIR%\features\org.talend.rcp.branding.%PRODUCTNAME%\%PRODUCTNAME%license.txt
//
// You should have received a copy of the agreement
// along with this program; if not, write to Talend SA
// 9 rue Pages 92150 Suresnes, France
//
// ============================================================================

package routines;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PushbackInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * created by talend on 2016-04-08 Detailled comment.
 *
 */
public class DataMasking {

    static final String ALGO = "AES"; //$NON-NLS-1$

    static final String GCMALGO = "AES/GCM/NoPadding"; //$NON-NLS-1$

    static final String UNICODE_FORMAT = "UTF8"; //$NON-NLS-1$

    static final String DES_ENCRYPTION_SCHEME = "DES"; //$NON-NLS-1$

    private static final int DEFAULT_IV_LENGTH = 16;

    public static final String NULL_PARAMETER_MESSAGE = "The parameter should not be null"; //$NON-NLS-1$

    public static final String EMPTY_PARAMETER_MESSAGE = "String is empty"; //$NON-NLS-1$

    private static final String KEY_GEN_ALGO = "PBKDF2WithHmacSHA256"; //$NON-NLS-1$

    static final Random random = new SecureRandom();

    static final BASE64Encoder b64Encoder = new DataMasking().new BASE64Encoder();

    static final BASE64Decoder b64Dencoder = new DataMasking().new BASE64Decoder();

    public static final Function<byte[], String> BASE64_ENCODER = bytes -> Base64.getEncoder().encodeToString(bytes);

    public static final Function<byte[], byte[]> BASE64_DECODER = bytes -> Base64.getDecoder().decode(bytes);

    public static class DataMaskingRoutineException extends RuntimeException {

        private static final long serialVersionUID = -8622896150657449668L;

        public DataMaskingRoutineException() {
            super();
        }

        public DataMaskingRoutineException(String s) {
            super(s);
        }

        public DataMaskingRoutineException(String s, Object o) {
            super(s);
            System.out.println(o);
        }

    }

    /**
     * createMD2: Calculate MD2 hash value from String.
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} string("foo") message: The string need to be masked.
     *
     * {example} createMD2("foo") return is d11f8ce29210b4b50c5e67533b699d02
     *
     *
     */
    public static String createMD2(String message) {
        if (message == null) {
            return "Input String for MD2 calculation is missing"; //$NON-NLS-1$
        } /* MD2 Calculation */
        MessageDigest md2Instance = null;
        try {
            md2Instance = MessageDigest.getInstance("MD2"); //$NON-NLS-1$
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        md2Instance.reset();
        md2Instance.update(message.getBytes());
        byte[] result = md2Instance.digest();

        /* Return */
        StringBuffer hexString = new StringBuffer();
        for (byte element : result) {
            if (element <= 15 && element >= 0) {
                hexString.append("0"); //$NON-NLS-1$
            }
            hexString.append(Integer.toHexString(0xFF & element));
        }
        return hexString.toString();

    }

    /**
     * createMD5: Calculate MD5 hash value from String.
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} string("foo") message: The string need to be masked.
     *
     * {example} createMD5("foo") result is acbd18db4cc2f85cedef654fccc4a4d8
     *
     */

    public static String createMD5(String message) {
        if (message == null) {
            return "Input String for MD5 calculation is missing"; //$NON-NLS-1$
        }

        /* Calculation */
        MessageDigest thisMD5 = null;
        try {
            thisMD5 = MessageDigest.getInstance("MD5"); //$NON-NLS-1$
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        thisMD5.reset();
        thisMD5.update(message.getBytes());
        byte[] result = thisMD5.digest();

        /* Return */
        StringBuffer hexString = new StringBuffer();
        for (byte element : result) {
            if (element <= 15 && element >= 0) {
                hexString.append("0"); //$NON-NLS-1$
            }
            hexString.append(Integer.toHexString(0xFF & element));
        }
        return hexString.toString();

    }

    /**
     * CreditCard Masking: Masks a 16 digit credit card number with a defined character from 5th to 12th place.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} string("0123456789012345") ccnum: The string needs to be masked.
     *
     * {param} string("*") maskingChar: The masking Character.
     *
     * {example} maskCreditCardNumber("0123456789012345","*") result is 0123********2345
     *
     */

    public static String maskCreditCardNumber(String ccnum, String maskingChar) {
        if (ccnum == null || maskingChar == null) {
            return NULL_PARAMETER_MESSAGE;
        }
        int total = ccnum.length();
        int startlen = 4, endlen = 4;
        int masklen = total - (startlen + endlen);
        if (ccnum.length() != 16) {
            return "No Credit Card Number - length not 16 char"; //$NON-NLS-1$
        } else {

            StringBuffer maskedbuf = new StringBuffer(ccnum.substring(0, startlen));
            for (int i = 0; i < masklen; i++) {
                maskedbuf.append(maskingChar);
            }
            maskedbuf.append(ccnum.substring(startlen + masklen, total));
            String masked = maskedbuf.toString();

            return masked;
        }
    }

    /**
     * Random String: Create a random String of defined length.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} int(5) valueLength: The length of the string.
     *
     * {example} createRandomString(5) result maybe is "1auA5","11uyd" or "A1c8j"
     *
     */

    public static String createRandomString(int valueLength) {
        String allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"; //$NON-NLS-1$
        return createRandomString(valueLength, allowedChars);
    }

    /**
     * Random String: Create a random String of defined length.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} int(5) valueLength: The length of the string.
     *
     * {param} String("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") allowedChars: The Sting which
     * the chacter of random string get from.
     *
     * {example} createRandomString(5,"a") result must be "aaaaa"
     *
     */

    public static String createRandomString(int valueLength, String allowedChars) {
        if (allowedChars == null || allowedChars.length() == 0) {
            return "Length of allowedChars must be greater than 0 and not be null"; //$NON-NLS-1$
        }
        String rdString = ""; //$NON-NLS-1$

        if (valueLength == 0) {
            return "Length of valueLength must be greater than 0"; //$NON-NLS-1$
        } else {
            StringBuilder builder = new StringBuilder();
            int maxChar = allowedChars.length();
            int i = 0;
            for (i = 0; i <= valueLength - 1; i++) {
                int value = random.nextInt(maxChar);
                builder.append(allowedChars.charAt(value));
                rdString = builder.toString();
            }
            return rdString;
        }
    }

    /**
     * Encrypt String: Encrypts a string using AES 128 .
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} String("foo") encryptString: The string to be encrypted.
     * 
     * {param} byte[](new byte[] { 'T', 'a', 'l', 'e', 'n', 'd', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' })
     * keyValue: the
     * key material of the secret key. The contents of the array are copied to protect against subsequent modification.
     * 
     * {example} encryptAES("foo", new byte[] { 'T', 'a', 'l', 'e', 'n', 'd', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' })
     * result is UQ0VJZq5ymFkMYQeDrPi0A==
     *
     * @deprecated use {@link #encryptAESGCM(String, String, int)} instead of it
     * 
     */

    @Deprecated
    public static String encryptAES(String encryptString, byte[] keyValue) {

        if (encryptString == null || keyValue == null) {
            return NULL_PARAMETER_MESSAGE;
        }
        if (encryptString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }
        try {
            Key key = new SecretKeySpec(keyValue, ALGO);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = cipher.doFinal(encryptString.getBytes());
            String encryptedValue = b64Encoder.encode(encVal);
            return encryptedValue;

        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage(), e);
        }
    }


    /**
     * Encrypt String: Encrypts a string using AES GCM 128 .
     * 
     * {talendTypes} String
     * 
     * {Category} Data Masking
     * 
     * {param} String("foo") encryptString: The string to be encrypted.
     * 
     * {param} String("TalendMainKey123") the main key used to encrypt the data.
     * 
     * {example} encryptAESGCM("foo","TalendMainKey123") result could be
     * +ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4= (but it should change from an execution to another).
     * 
     */

    public static String encryptAESGCM(String encryptString, String mainKey) {

        return encryptAESGCM(encryptString, mainKey, DEFAULT_IV_LENGTH);
    }

    /**
     * Encrypt String: Encrypts a string using AES GCM 128 .
     * 
     * {talendTypes} String
     * 
     * {Category} Data Masking
     * 
     * {param} String("foo") encryptString: The string to be encrypted.
     * 
     * {param} String("TalendMainKey123") the main key used to encrypt the data.
     * 
     * {param} int the length of initializationVector. must be one of 12/13/14/15/16.
     * 
     * {example} encryptAESGCM("foo","TalendMainKey123",16) result could be
     * +ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4= (but it should change from an execution to another).
     * 
     */

    public static String encryptAESGCM(String encryptString, String mainKey, int ivLength) {

        if (encryptString == null || mainKey == null) {
            return NULL_PARAMETER_MESSAGE;
        }

        if (encryptString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }

        try {
            return encrypt(encryptString, mainKey, ivLength);
        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage(), e);
        }
    }



    /**
     * decrypt String: Decrypts a string using AES 128.
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} String("UQ0VJZq5ymFkMYQeDrPi0A==") encryptedString: The string to be decrypted.
     *
     * {param} byte[](new byte[] { 'T', 'a', 'l', 'e', 'n', 'd', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' })
     * keyValue: the key material of the secret key. The contents of the array are copied to protect against subsequent
     * modification.
     * 
     * {example} decryptAES("UQ0VJZq5ymFkMYQeDrPi0A==",new byte[] { 'T', 'a', 'l', 'e', 'n', 'd', 's', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' })
     * result is "foo"
     * 
     * @deprecated use {@link #decryptAESGCM(String, String, int)} instead of it
     * 
     */

    @Deprecated
    public static String decryptAES(String encryptedString, byte[] keyValue) {

        if (encryptedString == null || keyValue == null) {
            return NULL_PARAMETER_MESSAGE;
        }

        if (encryptedString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }
        try {
            Key key = new SecretKeySpec(keyValue, ALGO);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decordedValue = b64Dencoder.decodeBuffer(encryptedString);
            byte[] decValue = cipher.doFinal(decordedValue);
            String decryptedValue = new String(decValue);
            return decryptedValue;

        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage(), e);
        }
    }

    /**
     * decrypt String: Decrypts a string using AES GCM 128.
     * 
     * {talendTypes} String
     * 
     * {Category} Data Masking
     * 
     * {param} String("+ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4=") encryptedString: The string to be decrypted.
     * 
     * {param} String("TalendMainKey123") the main key used to decrypt the data.
     * 
     * {param} int the length of initializationVector. must be one of 12/13/14/15/16.
     * 
     * {example} decryptAESGCM("+ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4=","TalendMainKey123",16) result
     * is "foo"
     * 
     */

    public static String decryptAESGCM(String encryptedString, String mainKey, int ivLength) {

        if (encryptedString == null || mainKey == null) {
            return NULL_PARAMETER_MESSAGE;
        }

        if (encryptedString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }

        try {
            return decrypt(encryptedString, mainKey, ivLength);

        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage(), e);
        }

    }

    /**
     * decrypt String: Decrypts a string using AES GCM 128.
     * 
     * {talendTypes} String
     * 
     * {Category} Data Masking
     * 
     * {param} String("+ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4=") encryptedString: The string to be decrypted.
     * 
     * {param} String("TalendMainKey123") the main key used to decrypt the data.
     * 
     * {example} decryptAESGCM("+ngs4RohAx8OvInmioRwRYS0pymcNkQJCKqsdUPZqUZppN4=","TalendMainKey123") result
     * is "foo"
     * 
     */

    public static String decryptAESGCM(String encryptedString, String mainKey) {

        return decryptAESGCM(encryptedString, mainKey, DEFAULT_IV_LENGTH);
    }

    /**
     * Encrypt String: Encrypts a string using DES .
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} String("foo") unencryptedString: The string to be encrypted.
     *
     * {param} String("ThisIsSecretEncryptionKey") myEncryptionKey: the string with the DES key material.
     *
     * {example} encryptDES("foo") result is DmNj+x2LUXA=
     *
     * @throws Exception
     */

    public static String encryptDES(String unencryptedString, String myEncryptionKey) {

        if (unencryptedString == null || myEncryptionKey == null) {
            return NULL_PARAMETER_MESSAGE;
        }
        if (unencryptedString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }
        try {
            String encryptedString = null;

            String myEncryptionScheme = DES_ENCRYPTION_SCHEME;
            byte[] keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
            KeySpec myKeySpec = new DESKeySpec(keyAsBytes);
            SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance(myEncryptionScheme);
            Cipher encipher = Cipher.getInstance(myEncryptionScheme);
            SecretKey key = mySecretKeyFactory.generateSecret(myKeySpec);

            encipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
            byte[] encryptedText = encipher.doFinal(plainText);
            encryptedString = b64Encoder.encode(encryptedText);

            return encryptedString;

        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage());
        }

    }

    /**
     * Decrypt String: Decrypts a string using DES .
     * warning: this is not considered a secure function.
     *
     *
     * {talendTypes} String
     *
     * {Category} Data Masking
     *
     * {param} String("DmNj+x2LUXA=") encryptedString: the string with the DES key material.
     *
     * {param} String("ThisIsSecretEncryptionKey") myDecryptionKey: The string to be encrypted.
     *
     * {example} decryptDES("DmNj+x2LUXA=") result is "foo"
     *
     */

    public static String decryptDES(String encryptedString, String myDecryptionKey) {

        if (encryptedString == null || myDecryptionKey == null) {
            return NULL_PARAMETER_MESSAGE;
        }

        if (encryptedString.length() == 0) {
            return EMPTY_PARAMETER_MESSAGE;
        }
        try {
            String decryptedText = null;

            String myDecryptionScheme = DES_ENCRYPTION_SCHEME;

            byte[] keyAsBytes = myDecryptionKey.getBytes(UNICODE_FORMAT);

            KeySpec myKeySpec = new DESKeySpec(keyAsBytes);
            Cipher decipher = Cipher.getInstance(myDecryptionScheme);
            SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance(myDecryptionScheme);
            SecretKey key = mySecretKeyFactory.generateSecret(myKeySpec);

            decipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedText = b64Dencoder.decodeBuffer(encryptedString);
            byte[] plainText = decipher.doFinal(encryptedText);

            StringBuilder stringBuilder = new StringBuilder();
            for (byte element : plainText) {
                stringBuilder.append((char) element);
            }
            decryptedText = stringBuilder.toString();
            return decryptedText;

        } catch (Exception e) {
            throw new DataMaskingRoutineException(e.getMessage(), e);
        }

    }

    /**
     * Blurring ADD: Adds a random value from a certain range to an Integer value. Make new value random around the
     * input number
     *
     * {talendTypes} integer
     *
     * {Category} Data Masking
     *
     * {param} int(1) basevalue: Any return value will base this value.
     *
     * {param} int(5) rangefrom: Minimum value which make basevalue changed.It could be a positive integer or negative
     * integer
     *
     * {param} int(10) rangeto: Maximum value which make basevalue changed.It could be a positive integer or negative
     * integer.
     *
     * {example}
     * blurNumber(1,5,10) result is between [6,11)
     * blurNumber(1,10,5) result is between [6,11)
     * blurNumber(1,-10,-5) result is between [-9,-4)
     * blurNumber(1,-10,10) result is between [-9,11)
     */
    public static int blurNumber(int basevalue, int rangefrom, int rangeto) {
        int range = rangeto - rangefrom;
        int randomInt = ((range >= 0 ? 1 : -1) * random.nextInt(Math.abs(range))) + rangefrom;
        return basevalue + randomInt;
    }

    /**
     * Blurring ADD: Adds a random value from a certain range to an long value. Make new value random around the input
     * number
     *
     *
     * {talendTypes} long
     *
     * {Category} Data Masking
     *
     * {param} long(1) basevalue: Any return value will around this value.
     *
     * {param} int(5) rangefrom: Minimum value which make basevalue changed.It must be a positive integer.
     *
     * {param} int(10) rangeto: Maximum value which make basevalue changed.It must be a positive integer.
     *
     * {example}
     * blurNumber(1,5,10) # returns any long between [6,11)
     * blurNumber(1,10,5) # returns any long between [6,11)
     */
    public static long blurNumber(long basevalue, int rangefrom, int rangeto) {
        int range = rangeto - rangefrom;
        int randomInt = ((range >= 0 ? 1 : -1) * random.nextInt(Math.abs(range))) + rangefrom;
        return basevalue + randomInt;
    }

    /**
     * Blurring ADD: Adds a random value from a certain range to an double value. Make new value random around the input
     * number
     *
     *
     * {talendTypes} double
     *
     * {Category} Data Masking
     *
     * {param} double(1.5d) basevalue: Any return value will around this value.
     *
     * {param} int(5) rangefrom: Minimum value which make basevalue changed.It must be a positive integer.
     *
     * {param} int(10) rangeto: Maximum value which make basevalue changed.It must be a positive integer.
     *
     * {example}
     * blurNumber(1.5,5,10) # returns any double between [6.5,11.5)
     * blurNumber(1.5,10,5) # returns any double between [6.5,11.5)
     *
     */
    public static double blurNumber(double basevalue, int rangefrom, int rangeto) {
        double range = 1.0 * (rangeto - rangefrom);
        double randomInt = ((range >= 0 ? 1 : -1) * random.nextDouble() * Math.abs(range)) + rangefrom;
        return basevalue + randomInt;
    }

    /**
     * Blurring ADD: Adds a random value from a certain range to an float value. Make new value random around the input
     * number
     *
     *
     * {talendTypes} float
     *
     * {Category} Data Masking
     *
     * {param} float(1.5) basevalue: Any return value will around this value.
     *
     * {param} int(5) rangefrom: Minimum value which make basevalue changed.It must be a positive integer.
     *
     * {param} int(10) rangeto: Maximum value which make basevalue changed.It must be a positive integer.
     *
     * {example}
     * blurNumber(1.5,5,10) # returns any integer between [6.5,11.5)
     * blurNumber(1.5,10,5) # returns any integer between [6.5,11.5)
     *
     */
    public static float blurNumber(float basevalue, int rangefrom, int rangeto) {
        float range = 1.0f * (rangeto - rangefrom);
        float randomInt = ((range >= 0 ? 1 : -1) * random.nextFloat() * Math.abs(range)) + rangefrom;
        return basevalue + randomInt;
    }

    /**
     * IP-Adress Masking: creates a random ip-address.
     *
     *
     * {talendTypes} string
     *
     * {Category} Data Masking
     *
     * {param} Empty
     *
     * {example} createIPAddress() result maybe is 192.168.33.111
     *
     */

    public static String createIPAddress() {

        int randomInt1 = random.nextInt(255);
        int randomInt2 = random.nextInt(255);
        int randomInt3 = random.nextInt(255);
        int randomInt4 = random.nextInt(255);

        String ip1 = String.valueOf(randomInt1);
        String ip2 = String.valueOf(randomInt2);
        String ip3 = String.valueOf(randomInt3);
        String ip4 = String.valueOf(randomInt4);

        String ip = ip1.concat(".").concat(ip2).concat(".").concat(ip3).concat(".").concat(ip4); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

        return ip;

    }

    /**
     * IP-Adress Masking with Domain: creates a random ip-address while keeping the domain part of the ip-address.
     *
     *
     * {talendTypes} string
     *
     * {Category} Data Masking
     *
     * {param} String("192.168.33.111") It should be a full IP address.
     *
     * {example} createIPAddressKeepDomain("192.168.33.111") result maybe is "192.168.77.213"
     *
     */

    public static String createIPAddressKeepDomain(String inputval) {
        if (inputval == null) {
            return NULL_PARAMETER_MESSAGE;
        }

        int firstDot = inputval.indexOf("."); //$NON-NLS-1$
        int secondDot = inputval.indexOf(".", firstDot + 2); //$NON-NLS-1$

        String substr = inputval.substring(0, secondDot);

        int randomInt1 = random.nextInt(255);
        int randomInt2 = random.nextInt(255);

        String ip1 = String.valueOf(randomInt1);
        String ip2 = String.valueOf(randomInt2);

        String ip = substr.concat(".").concat(ip1).concat(".").concat(ip2); //$NON-NLS-1$ //$NON-NLS-2$

        return ip;

    }

    /**
     * Random Date (fromYear,toYear: Returns a random date as String .
     *
     *
     * {talendTypes}
     *
     * {Category} Data Masking
     *
     * {param} int(1900) yearFrom: Start year of range
     *
     * {param} int(2012) yearTo: end year of range
     *
     * {example} createRandomDate(1900,2012) result should be in the range [1900,2099]
     *
     */

    public static String createRandomDate(int yearFrom, int yearTo) {

        String yr;

        Calendar cal = Calendar.getInstance();

        int dayOfYear = random.nextInt(cal.getActualMaximum(Calendar.DAY_OF_YEAR) - 1);

        int year = random.nextInt(yearTo - yearFrom);

        if (year <= 100) {
            Integer myYear = new Integer(year);
            yr = "19" + myYear.toString(); //$NON-NLS-1$
        } else {
            Integer myYear = new Integer(year);
            yr = "20" + myYear.toString().substring(1, 3); //$NON-NLS-1$
        }

        year = Integer.parseInt(yr);

        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.DAY_OF_YEAR, dayOfYear);

        Date randomDate = cal.getTime();

        return randomDate.toString();
    }

    /**
     * Default Masking (Set_DefaultValue: Returns a default value as String) .
     *
     *
     * {talendTypes}
     *
     * {Category} Data Masking
     *
     * {param} String("foo") value: The value which should be default one.
     *
     * {example} setDefaultValue("foo") result is "foo"
     *
     */

    public static String setDefaultValue(String value) {
        String initString = ""; //$NON-NLS-1$

        String outString = initString + value;

        int StringLength = outString.length();

        if (StringLength == 0) {
            return "No default value"; //$NON-NLS-1$
        } else {
            return outString;
        }

    }

    private abstract class CharacterEncoder {

        public CharacterEncoder() {
        }

        protected abstract int bytesPerAtom();

        protected abstract int bytesPerLine();

        protected void encodeBufferPrefix(OutputStream outputstream) throws IOException {
            new PrintStream(outputstream);
        }

        protected void encodeBufferSuffix(OutputStream outputstream) throws IOException {
            // nothing here
        }

        protected void encodeLinePrefix(OutputStream outputstream, int i) throws IOException {
            // nothing here
        }

        protected void encodeLineSuffix(OutputStream outputstream) throws IOException {
            // nothing here
        }

        protected abstract void encodeAtom(OutputStream outputstream, byte abyte0[], int i, int j) throws IOException;

        protected int readFully(InputStream inputstream, byte abyte0[]) throws IOException {
            for (int i = 0; i < abyte0.length; i++) {
                int j = inputstream.read();
                if (j == -1) {
                    return i;
                }
                abyte0[i] = (byte) j;
            }

            return abyte0.length;
        }

        public void encode(InputStream inputstream, OutputStream outputstream) throws IOException {
            byte abyte0[] = new byte[bytesPerLine()];
            encodeBufferPrefix(outputstream);
            do {
                int j = readFully(inputstream, abyte0);
                if (j == 0) {
                    break;
                }
                encodeLinePrefix(outputstream, j);
                for (int i = 0; i < j; i += bytesPerAtom()) {
                    if (i + bytesPerAtom() <= j) {
                        encodeAtom(outputstream, abyte0, i, bytesPerAtom());
                    } else {
                        encodeAtom(outputstream, abyte0, i, j - i);
                    }
                }

                if (j < bytesPerLine()) {
                    break;
                }
                encodeLineSuffix(outputstream);
            } while (true);
            encodeBufferSuffix(outputstream);
        }

        public String encode(byte abyte0[]) {
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            ByteArrayInputStream bytearrayinputstream = new ByteArrayInputStream(abyte0);
            String s = null;
            try {
                encode(bytearrayinputstream, bytearrayoutputstream);
                s = bytearrayoutputstream.toString("8859_1"); //$NON-NLS-1$
            } catch (Exception exception) {
                throw new Error("ChracterEncoder::encodeBuffer internal error"); //$NON-NLS-1$
            }
            return s;
        }
    }

    private class BASE64Encoder extends CharacterEncoder {

        public BASE64Encoder() {
        }

        @Override
        protected int bytesPerAtom() {
            return 3;
        }

        @Override
        protected int bytesPerLine() {
            return 57;
        }

        @Override
        protected void encodeAtom(OutputStream outputstream, byte abyte0[], int i, int j) throws IOException {
            if (j == 1) {
                byte byte0 = abyte0[i];
                int k = 0;
                outputstream.write(pem_array[byte0 >>> 2 & 0x3f]);
                outputstream.write(pem_array[(byte0 << 4 & 0x30) + (k >>> 4 & 0xf)]);
                outputstream.write(61);
                outputstream.write(61);
            } else if (j == 2) {
                byte byte1 = abyte0[i];
                byte byte3 = abyte0[i + 1];
                int l = 0;
                outputstream.write(pem_array[byte1 >>> 2 & 0x3f]);
                outputstream.write(pem_array[(byte1 << 4 & 0x30) + (byte3 >>> 4 & 0xf)]);
                outputstream.write(pem_array[(byte3 << 2 & 0x3c) + (l >>> 6 & 3)]);
                outputstream.write(61);
            } else {
                byte byte2 = abyte0[i];
                byte byte4 = abyte0[i + 1];
                byte byte5 = abyte0[i + 2];
                outputstream.write(pem_array[byte2 >>> 2 & 0x3f]);
                outputstream.write(pem_array[(byte2 << 4 & 0x30) + (byte4 >>> 4 & 0xf)]);
                outputstream.write(pem_array[(byte4 << 2 & 0x3c) + (byte5 >>> 6 & 3)]);
                outputstream.write(pem_array[byte5 & 0x3f]);
            }
        }

    }

    private abstract class CharacterDecoder {

        protected abstract int bytesPerAtom();

        protected abstract int bytesPerLine();

        protected void decodeBufferPrefix(PushbackInputStream paramPushbackInputStream, OutputStream paramOutputStream)
                throws IOException {
            // nothing here
        }

        protected void decodeBufferSuffix(PushbackInputStream paramPushbackInputStream, OutputStream paramOutputStream)
                throws IOException {
            // nothing here
        }

        protected int decodeLinePrefix(PushbackInputStream paramPushbackInputStream, OutputStream paramOutputStream)
                throws IOException {
            return bytesPerLine();
        }

        protected void decodeLineSuffix(PushbackInputStream paramPushbackInputStream, OutputStream paramOutputStream)
                throws IOException {
            // nothing here
        }

        protected void decodeAtom(PushbackInputStream paramPushbackInputStream, OutputStream paramOutputStream, int paramInt)
                throws IOException {
            throw new CEStreamExhausted("CEStreamExhausted"); //$NON-NLS-1$
        }

        protected int readFully(InputStream paramInputStream, byte[] paramArrayOfByte, int paramInt1, int paramInt2)
                throws IOException {
            for (int i = 0; i < paramInt2; i++) {
                int j = paramInputStream.read();
                if (j == -1) {
                    return i == 0 ? -1 : i;
                }
                paramArrayOfByte[(i + paramInt1)] = (byte) j;
            }
            return paramInt2;
        }

        public void decodeBuffer(InputStream paramInputStream, OutputStream paramOutputStream) throws IOException {
            int j = 0;
            PushbackInputStream localPushbackInputStream = new PushbackInputStream(paramInputStream);
            decodeBufferPrefix(localPushbackInputStream, paramOutputStream);
            try {
                do {
                    int k = decodeLinePrefix(localPushbackInputStream, paramOutputStream);
                    int i;
                    for (i = 0; i + bytesPerAtom() < k; i += bytesPerAtom()) {
                        decodeAtom(localPushbackInputStream, paramOutputStream, bytesPerAtom());
                        j += bytesPerAtom();
                    }

                    if (i + bytesPerAtom() == k) {
                        decodeAtom(localPushbackInputStream, paramOutputStream, bytesPerAtom());
                        j += bytesPerAtom();
                    } else {
                        decodeAtom(localPushbackInputStream, paramOutputStream, k - i);
                        j += k - i;
                    }
                    decodeLineSuffix(localPushbackInputStream, paramOutputStream);
                } while (true);
            } catch (IOException e) {
                if (e.getMessage().equals("CEStreamExhausted")) { //$NON-NLS-1$
                    decodeBufferSuffix(localPushbackInputStream, paramOutputStream);
                } else {
                    throw e;
                }
            }
        }

        public byte[] decodeBuffer(String paramString) throws IOException {
            byte[] arrayOfByte = new byte[paramString.length()];
            paramString.getBytes(0, paramString.length(), arrayOfByte, 0);
            ByteArrayInputStream localByteArrayInputStream = new ByteArrayInputStream(arrayOfByte);
            ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
            decodeBuffer(localByteArrayInputStream, localByteArrayOutputStream);
            return localByteArrayOutputStream.toByteArray();
        }
    }

    private static final char[] pem_array = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '+', '/' };

    private static final byte[] pem_convert_array = new byte[256];

    static {
        for (int i = 0; i < 255; i++) {
            pem_convert_array[i] = -1;
        }
        for (int i = 0; i < pem_array.length; i++) {
            pem_convert_array[pem_array[i]] = (byte) i;
        }
    }

    private class BASE64Decoder extends CharacterDecoder {

        byte[] decode_buffer = new byte[4];

        @Override
        protected int bytesPerAtom() {
            return 4;
        }

        @Override
        protected int bytesPerLine() {
            return 72;
        }

        @Override
        protected void decodeAtom(PushbackInputStream inStream, OutputStream outStream, int rem) throws IOException {
            int i;
            byte a = -1, b = -1, c = -1, d = -1;

            if (rem < 2) {
                throw new CEFormatException("BASE64Decoder: Not enough bytes for an atom."); //$NON-NLS-1$
            }
            do {
                i = inStream.read();
                if (i == -1) {
                    throw new CEStreamExhausted("CEStreamExhausted"); //$NON-NLS-1$
                }
            } while (i == '\n' || i == '\r');
            decode_buffer[0] = (byte) i;

            i = readFully(inStream, decode_buffer, 1, rem - 1);
            if (i == -1) {
                throw new CEStreamExhausted("CEStreamExhausted"); //$NON-NLS-1$
            }

            if (rem > 3 && decode_buffer[3] == '=') {
                rem = 3;
            }
            if (rem > 2 && decode_buffer[2] == '=') {
                rem = 2;
            }
            switch (rem) {
            case 4:
                d = pem_convert_array[decode_buffer[3] & 0xff];
                // NOBREAK
            case 3:
                c = pem_convert_array[decode_buffer[2] & 0xff];
                // NOBREAK
            case 2:
                b = pem_convert_array[decode_buffer[1] & 0xff];
                a = pem_convert_array[decode_buffer[0] & 0xff];
                break;
            }

            switch (rem) {
            case 2:
                outStream.write((byte) (((a << 2) & 0xfc) | ((b >>> 4) & 3)));
                break;
            case 3:
                outStream.write((byte) (((a << 2) & 0xfc) | ((b >>> 4) & 3)));
                outStream.write((byte) (((b << 4) & 0xf0) | ((c >>> 2) & 0xf)));
                break;
            case 4:
                outStream.write((byte) (((a << 2) & 0xfc) | ((b >>> 4) & 3)));
                outStream.write((byte) (((b << 4) & 0xf0) | ((c >>> 2) & 0xf)));
                outStream.write((byte) (((c << 6) & 0xc0) | (d & 0x3f)));
                break;
            }
            return;
        }

    }

    private class CEStreamExhausted extends IOException {

        static final long serialVersionUID = -5889118049525891904L;

        public CEStreamExhausted(String paramString) {
            super(paramString);
        }
    }

    private class CEFormatException extends IOException {

        static final long serialVersionUID = -7139121221067081482L;

        public CEFormatException(String paramString) {
            super(paramString);
        }
    }

    private static synchronized byte[] generateInitializationVector(int length) {
        byte[] randomKey = new byte[length];
        new SecureRandom().nextBytes(randomKey);
        return randomKey;
    }


    /**
     * @return A {@link Cipher} using AES/GCM/NoPadding encryption.
     */
    private static Cipher getAesGcmCipher(int encryptMode, String mainKey, byte[] initializationVector)
            throws Exception {
        int ivLength = initializationVector.length;
        if (Stream.of(12, 13, 14, 15, 16).noneMatch(i -> i == ivLength)) {
            throw new IllegalArgumentException("Invalid IV length"); //$NON-NLS-1$
        }
        final Cipher cipher = Cipher.getInstance(GCMALGO);
        SecretKey key = new SecretKeySpec(generateSecretKeyFromPassword(mainKey, mainKey.length()), ALGO);
        final GCMParameterSpec spec = new GCMParameterSpec(ivLength * 8, initializationVector);
        cipher.init(encryptMode, key, spec);
        return cipher;
    }

    /**
     * This method generates a secret Key using the key-stretching algorithm PBKDF2 of
     * <a href="https://docs.oracle.com/javase/7/docs/api/javax/crypto/package-summary.html">javax.crypto</a>.
     * It is basically a hashing algorithm slow by design, in order to increase the time
     * required for an attacker to try a lot of passwords in a bruteforce attack.
     * <br>
     * About the salt :
     * <ul>
     * <li>The salt is not secret, the use of Random is not critical and ensure determinism.</li>
     * <li>The salt is important to avoid rainbow table attacks.</li>
     * <li>The salt should be generated with SecureRandom() in case the passwords are stored.</li>
     * <li>In that case the salt should be stored in plaintext next to the password and a unique user identifier.</li>
     * </ul>
     *
     * @param password a password given as a {@code String}.
     * @param keyLength key length to generate
     * @return a {@code SecretKey} securely generated.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static byte[] generateSecretKeyFromPassword(String password, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[keyLength];
        new Random(password.hashCode()).nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_GEN_ALGO);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keyLength << 3);
        return factory.generateSecret(spec).getEncoded();
    }

    private static String encrypt(String data, String mainKey, int ivLength) throws Exception {
        final byte[] dataBytes = data.getBytes(UNICODE_FORMAT);
        byte[] initializationVector = generateInitializationVector(ivLength);
        final Cipher cipher = getAesGcmCipher(Cipher.ENCRYPT_MODE, mainKey, initializationVector);

        final byte[] encryptedData = cipher.doFinal(dataBytes);
        final byte[] encryptedBytes = new byte[encryptedData.length + ivLength];
        System.arraycopy(initializationVector, 0, encryptedBytes, 0, ivLength);
        System.arraycopy(encryptedData, 0, encryptedBytes, ivLength, encryptedData.length);

        return BASE64_ENCODER.apply(encryptedBytes);
    }


    private static String decrypt(String data, String mainKey, int ivLength) throws Exception {
        final byte[] encryptedBytes = BASE64_DECODER.apply(data.getBytes(UNICODE_FORMAT));

        final byte[] initializationVector = new byte[ivLength];
        System.arraycopy(encryptedBytes, 0, initializationVector, 0, ivLength);

        final Cipher cipher = getAesGcmCipher(Cipher.DECRYPT_MODE, mainKey, initializationVector);
        return new String(cipher.doFinal(encryptedBytes, ivLength, encryptedBytes.length - ivLength),
                UNICODE_FORMAT);
    }

}